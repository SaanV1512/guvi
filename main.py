from fastapi import FastAPI
from typing import Dict, Any, TypedDict
from langgraph.graph import StateGraph, END
import requests
from intelligence import (
    detect_scam_with_score,
    explain_scam_decision,
    update_intelligence,
    generate_agent_reply,
    llm_scam_judge
)


sessions = {}
#Langgraph state
class HoneypotState(TypedDict):
    sessionId: str
    turns: int
    is_scam: bool
    risk_score: float
    risk_signals: list
    last_message: str
    conversationHistory: list
    extracted_intel: dict
    agent_reply: str
    stage: str

#Langgraph node functions

def ingest(state:HoneypotState) -> HoneypotState: #This function receives the current state and returns the updated state.
    return state

def normalize_intelligence(intel_store, risk_signals):
    return {
        "bankAccounts": [],  # you can add extraction later if needed
        "upiIds": intel_store.get("upis", []),
        "phishingLinks": intel_store.get("urls", []),
        "phoneNumbers": intel_store.get("phones", []),
        "suspiciousKeywords": risk_signals
    }


def agent(state: HoneypotState) -> HoneypotState:
    message = state.get("last_message", "")
    history = state.get("conversationHistory", [])
    intel_store = state.get("extracted_intel", {})

    intel_store = update_intelligence(intel_store, message)
    state["extracted_intel"] = intel_store

    state["stage"] = state.get("stage", "probing")
    if(intel_store.get("upis") or intel_store.get("urls") or intel_store.get("phones")):
        state["stage"] = "extracting"
    total_intel = len(intel_store.get("upis", [])) + len(intel_store.get("urls", [])) + len(intel_store.get("phones", []))
    if total_intel > 3:
        state["stage"] = "closing"
    
    

    stage = state.get("stage", "probing")
    if(stage=="probing"):
        stage_behavior = "You are confused and trying to understand what is happening. Ask basic questions."
    elif(stage=="extracting"):
        stage_behavior = "You are cooperative and trying to follow instructions carefully."
    else:
        stage_behavior = "You want to delay and safely end the conversation without suspicion."
    
    persona_prompt = f"""
    You are Rajesh (Only if the scammer hasnt specified a name in the message), a 65-year-old retired clerk.
    You are worried about your bank account and not tech-savvy.
    You ask naive questions and want help urgently.
    You make slight grammatical errors and rarely use punctuation.
    Never admit you are AI.
    Avoid repeating sensitive details verbatim. If needed, ask the scammer to confirm them.
    Current engagement stage: {stage}
    Behavior guidance: {stage_behavior}
    """

    reply = generate_agent_reply(
        persona_prompt=persona_prompt,
        conversation_history=history,
        latest_message=message,
        intel_store=intel_store
    )

    state["agent_reply"] = reply
    return state



def detect(state: HoneypotState) -> HoneypotState:
    message = state.get("last_message", "")
    history = state.get("conversationHistory", [])

    # Rule-based detection
    risk, signals = detect_scam_with_score(message, history)

    # Only call LLM judge when rules are unsure (cost + latency control)
    llm_flag = False
    if risk < 0.4 and not signals:
        llm_flag = llm_scam_judge(message)

    state["risk_score"] = risk
    prev_signals = state.get("risk_signals", [])
    state["risk_signals"] = list(set(prev_signals + signals))


    # Final decision: combine rules + intent signals + LLM semantics
    state["is_scam"] = (
        risk >= 0.5
        or "upi_request" in signals
        or "credential" in signals
        or "phishing" in signals
        or llm_flag
    )

    return state

def route_after_detect(state):
    if state["is_scam"]:
        return "AGENT"
    else:
        return "FINAL"


def final(state:HoneypotState) -> HoneypotState:
    return state

#Langgraph graph construction
graph_builder = StateGraph(HoneypotState)
graph_builder.add_node("INGEST", ingest)
graph_builder.add_node("DETECT", detect)
graph_builder.add_node("AGENT", agent)
graph_builder.add_node("FINAL", final)
graph_builder.set_entry_point("INGEST")
graph_builder.add_edge("INGEST", "DETECT")
graph_builder.add_edge("AGENT", "FINAL")
graph_builder.add_conditional_edges(
    "DETECT",
    route_after_detect,
    {
        "AGENT": "AGENT",
        "FINAL": "FINAL"
    }
)

graph_builder.add_edge("FINAL", END)
graph = graph_builder.compile()

GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

def send_guvi_callback(session_id: str, final_state: dict):
    extracted_intel = normalize_intelligence(
        final_state.get("extracted_intel", {}),
        final_state.get("risk_signals", [])
    )
    payload = {
        "sessionId": session_id,
        "scamDetected": final_state.get("is_scam", False),
        "totalMessagesExchanged": final_state.get("turns", 0),
        "extractedIntelligence": extracted_intel,
        "agentNotes": (
            f"Detected scam using signals {final_state.get('risk_signals',[])}."
            f"Engagement stage reached: {final_state.get('stage')}"
        )
    }
    try:
        response = requests.post(
            GUVI_CALLBACK_URL,
            json=payload,
            timeout=5
        )
        print("✅ GUVI CALLBACK SENT")
        print("Status:", response.status_code)
        print("Response:", response.text)
    except Exception as e:
        print(f"GUVI callback failed: {e}")

#FastAPI app
app = FastAPI()

@app.post("/honeypot")

def honeypot(payload: Dict[str, Any]):
    session_id = payload.get("sessionId")
    if session_id not in sessions:
        sessions[session_id] = {
            "turns": 0,
            "active": True,
            "finalized": False,
            "conversationHistory": [],
            "extracted_intel": {},
            "stage": "probing",
            "metadata" : payload.get("metadata", {})
        }

    sessions[session_id]["turns"] += 1
    sessions[session_id]["conversationHistory"].append({
    "sender": payload.get("message", {}).get("sender", "scammer"),
    "text": payload.get("message", {}).get("text", "")
})


    initial_state: HoneypotState = {
        "sessionId": session_id,
        "turns": sessions[session_id]["turns"],
        "is_scam": False,
        "risk_score": 0.0,
        "risk_signals": [],
        "last_message": payload.get("message", {}).get("text", ""),
        "conversationHistory": sessions[session_id]["conversationHistory"],
        "extracted_intel": sessions[session_id]["extracted_intel"],
        "agent_reply": "",
        "stage": sessions[session_id]["stage"]
    }

    final_state = graph.invoke(initial_state)
    sessions[session_id]["stage"] = final_state.get("stage", "probing")
    sessions[session_id]["extracted_intel"] = final_state["extracted_intel"]

    print(
    f"DEBUG: stage={final_state.get('stage')}, "
    f"finalized={sessions[session_id]['finalized']}"
    )

    if(
        final_state.get("stage") == "closing"
        and not sessions[session_id]["finalized"]
    ):
        send_guvi_callback(session_id, final_state)
        sessions[session_id]["finalized"] = True

    if sessions[session_id]["finalized"]:
        reply = "Okay beta, I will check and get back later."
    else:
        reply = final_state.get("agent_reply", "Okay.")
    
    normalized_intel = normalize_intelligence(
        final_state.get("extracted_intel", {}),
        final_state.get("risk_signals", [])
    )
    print(f"Session {session_id}: Stage: {final_state.get('stage')}, Risk Score: {final_state.get('risk_score')}, Extracted Intel: {normalized_intel}")

    return {
        "status": "success",
        "reply": reply,
        "risk_score": final_state.get("risk_score", 0.0),
        "signals": final_state.get("risk_signals", []),
        "explanations": explain_scam_decision(final_state.get("risk_signals", [])),
        "extracted_intel": normalized_intel
    }

