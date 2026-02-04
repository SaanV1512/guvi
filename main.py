from fastapi import FastAPI
from typing import Dict, Any, TypedDict
from langgraph.graph import StateGraph, END
from intelligence import (
    detect_scam_with_score,
    explain_scam_decision,
    update_intelligence,
    generate_agent_reply
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

#Langgraph node functions

def ingest(state:HoneypotState) -> HoneypotState: #This function receives the current state and returns the updated state.
    return state


def agent(state: HoneypotState) -> HoneypotState:
    message = state.get("last_message", "")
    history = state.get("conversationHistory", [])

    intel_store = state.get("extracted_intel", {})
    intel_store = update_intelligence(intel_store, message)
    state["extracted_intel"] = intel_store

    persona_prompt = """
    You are Rajesh (Only if the scammer hasnt specified a name in the message), a 65-year-old retired clerk.
    You are worried about your bank account and not tech-savvy.
    You ask naive questions and want help urgently.
    You make slight grammatical errors and rarely use punctuation.
    Never admit you are AI.
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
    risk, signals = detect_scam_with_score(message, history)
    state["risk_score"] = risk
    state["risk_signals"] = signals
    state["is_scam"] = risk > 0.6

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

#FastAPI app
app = FastAPI()

@app.post("/honeypot")

def honeypot(payload: Dict[str, Any]):
    session_id = payload.get("sessionId")
    if session_id not in sessions:
        sessions[session_id] = {
            "turns": 0,
            "active": True,
            "conversationHistory": [],
            "extracted_intel": {}
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
        "agent_reply": ""
    }

    final_state = graph.invoke(initial_state)
    sessions[session_id]["extracted_intel"] = final_state["extracted_intel"]

    return {
        "status": "success",
        "reply": final_state.get("agent_reply", "Okay."),
        "risk_score": final_state.get("risk_score", 0.0),
        "signals": final_state.get("risk_signals", []),
        "extracted_intel": final_state.get("extracted_intel", {})
    }

