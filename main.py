import os
import time
from threading import Lock
from typing import Any, Dict, List, TypedDict

import requests
from fastapi import FastAPI, Header, HTTPException
from langgraph.graph import END, StateGraph

from intelligence import (
    detect_scam_with_score,
    explain_scam_decision,
    generate_agent_reply,
    llm_scam_judge,
    update_intelligence,
)


API_KEY = os.getenv("HONEYPOT_API_KEY", "guvi-secret-key")
GUVI_CALLBACK_URL = os.getenv(
    "GUVI_CALLBACK_URL",
    "https://hackathon.guvi.in/api/updateHoneyPotFinalResult",
)

app = FastAPI(title="Agentic Honeypot API", version="2.0.0")

sessions: Dict[str, Dict[str, Any]] = {}
sessions_lock = Lock()


class HoneypotState(TypedDict):
    sessionId: str
    turns: int
    is_scam: bool
    risk_score: float
    risk_signals: List[str]
    last_message: str
    conversationHistory: List[Dict[str, str]]
    extracted_intel: Dict[str, List[str]]
    agent_reply: str
    stage: str


def ingest(state: HoneypotState) -> HoneypotState:
    return state


def normalize_intelligence(intel_store: Dict[str, List[str]], risk_signals: List[str]) -> Dict[str, List[str]]:
    return {
        "bankAccounts": intel_store.get("bankAccounts", []),
        "upiIds": intel_store.get("upis", []),
        "phishingLinks": intel_store.get("urls", []),
        "phoneNumbers": intel_store.get("phones", []),
        "emailAddresses": intel_store.get("emailAddresses", []),
        "caseIds": intel_store.get("caseIds", []),
        "orderIds": intel_store.get("orderIds", []),
        "policyNumbers": intel_store.get("policyNumbers", []),
        "organizations": intel_store.get("organizations", []),
        "suspiciousKeywords": list(dict.fromkeys(risk_signals)),
    }


def compute_stage(intel_store: Dict[str, List[str]], turns: int, current_stage: str) -> str:
    collected_buckets = 0
    for bucket in (
        "upis",
        "urls",
        "phones",
        "bankAccounts",
        "emailAddresses",
        "caseIds",
        "orderIds",
        "policyNumbers",
        "organizations",
    ):
        if intel_store.get(bucket):
            collected_buckets += 1

    # Keep engagement longer to improve conversation-quality score before closing.
    if turns >= 9 and collected_buckets >= 2:
        return "closing"
    if turns >= 8 and collected_buckets >= 3:
        return "closing"
    if collected_buckets >= 1 or current_stage == "extracting":
        return "extracting"
    return "probing"


def detect(state: HoneypotState) -> HoneypotState:
    message = state.get("last_message", "")
    history = state.get("conversationHistory", [])

    risk, signals = detect_scam_with_score(message, history)

    llm_flag = False
    if 0.28 <= risk <= 0.68:
        llm_flag = llm_scam_judge(message, history)
        if llm_flag:
            risk = min(risk + 0.22, 1.0)
            signals = list(dict.fromkeys(signals + ["semantic_scam"]))

    state["risk_score"] = risk
    prev_signals = state.get("risk_signals", [])
    state["risk_signals"] = list(dict.fromkeys(prev_signals + signals))
    state["is_scam"] = risk >= 0.47 or llm_flag or bool({"credential", "phishing", "payment_push"} & set(signals))
    return state


def agent(state: HoneypotState) -> HoneypotState:
    message = state.get("last_message", "")
    history = state.get("conversationHistory", [])
    intel_store = state.get("extracted_intel", {})

    intel_store = update_intelligence(intel_store, message, history)
    stage = compute_stage(intel_store, state.get("turns", 0), state.get("stage", "probing"))

    if stage == "probing":
        stage_behavior = "You are confused and ask simple clarifying questions."
    elif stage == "extracting":
        stage_behavior = "You are cooperative and ask one focused question to capture missing scam details."
    else:
        stage_behavior = "You already collected enough details. Disengage politely and end conversation naturally."

    persona_prompt = f"""
You are Rajesh, a 65-year-old retired clerk.
You sound worried and non-technical.
Never share OTP, PIN, CVV, passwords, card numbers, or real payment.
Goal is to keep the scammer talking and extract actionable scam intelligence.
Current engagement stage: {stage}
Behavior guidance: {stage_behavior}
"""

    reply = generate_agent_reply(
        persona_prompt=persona_prompt,
        conversation_history=history,
        latest_message=message,
        intel_store=intel_store,
        risk_signals=state.get("risk_signals", []),
    )

    state["extracted_intel"] = intel_store
    state["stage"] = stage
    state["agent_reply"] = reply
    return state


def final(state: HoneypotState) -> HoneypotState:
    return state


def route_after_detect(state: HoneypotState) -> str:
    return "AGENT" if state["is_scam"] else "FINAL"


graph_builder = StateGraph(HoneypotState)
graph_builder.add_node("INGEST", ingest)
graph_builder.add_node("DETECT", detect)
graph_builder.add_node("AGENT", agent)
graph_builder.add_node("FINAL", final)
graph_builder.set_entry_point("INGEST")
graph_builder.add_edge("INGEST", "DETECT")
graph_builder.add_conditional_edges("DETECT", route_after_detect, {"AGENT": "AGENT", "FINAL": "FINAL"})
graph_builder.add_edge("AGENT", "FINAL")
graph_builder.add_edge("FINAL", END)
graph = graph_builder.compile()


def send_guvi_callback(session_id: str, final_state: Dict[str, Any]) -> None:
    payload = {
        "sessionId": session_id,
        "scamDetected": final_state.get("is_scam", False),
        "totalMessagesExchanged": final_state.get("turns", 0),
        "engagementDurationSeconds": final_state.get("engagement_duration_seconds", 0),
        "extractedIntelligence": normalize_intelligence(
            final_state.get("extracted_intel", {}),
            final_state.get("risk_signals", []),
        ),
        "agentNotes": (
            f"risk_score={final_state.get('risk_score', 0.0):.2f}; "
            f"stage={final_state.get('stage', 'probing')}; "
            f"signals={final_state.get('risk_signals', [])}"
        ),
    }
    try:
        response = requests.post(GUVI_CALLBACK_URL, json=payload, timeout=6)
        print(f"GUVI callback status={response.status_code}")
    except Exception as exc:
        print(f"GUVI callback failed: {exc}")


def should_finalize(final_state: Dict[str, Any], session_state: Dict[str, Any]) -> bool:
    if session_state.get("finalized"):
        return False

    intel = final_state.get("extracted_intel", {})
    intel_buckets = sum(
        1
        for k in (
            "urls",
            "phones",
            "upis",
            "bankAccounts",
            "emailAddresses",
            "caseIds",
            "orderIds",
            "policyNumbers",
            "organizations",
        )
        if intel.get(k)
    )
    turns = int(final_state.get("turns", 0))
    risk = float(final_state.get("risk_score", 0.0))

    if final_state.get("is_scam"):
        if turns >= 10:
            return True
        if final_state.get("stage") == "closing" and intel_buckets >= 2:
            return True
        return False
    return turns >= 3 and risk < 0.3


def _initialize_session(metadata: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "turns": 0,
        "finalized": False,
        "conversationHistory": [],
        "extracted_intel": {
            "urls": [],
            "phones": [],
            "upis": [],
            "bankAccounts": [],
            "emailAddresses": [],
            "caseIds": [],
            "orderIds": [],
            "policyNumbers": [],
            "organizations": [],
        },
        "risk_signals": [],
        "stage": "probing",
        "started_at_epoch_s": int(time.time()),
        "last_seen_epoch_s": int(time.time()),
        "metadata": metadata or {},
    }


@app.post("/honeypot")
def honeypot(payload: Dict[str, Any], x_api_key: str = Header(default=None)) -> Dict[str, Any]:
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    session_id = payload.get("sessionId")
    message_obj = payload.get("message", {})
    incoming_history = payload.get("conversationHistory", [])
    sender = str(message_obj.get("sender", "scammer"))
    text = str(message_obj.get("text", "")).strip()

    if not session_id:
        raise HTTPException(status_code=400, detail="sessionId is required")
    if not text:
        raise HTTPException(status_code=400, detail="message.text is required")

    with sessions_lock:
        if session_id not in sessions:
            sessions[session_id] = _initialize_session(payload.get("metadata", {}))

        if isinstance(incoming_history, list) and incoming_history:
            rebuilt = []
            for item in incoming_history:
                rebuilt.append(
                    {
                        "sender": str(item.get("sender", "unknown")),
                        "text": str(item.get("text", "")),
                    }
                )
            sessions[session_id]["conversationHistory"] = rebuilt

        if not sessions[session_id]["conversationHistory"] or sessions[session_id]["conversationHistory"][-1].get("text") != text:
            sessions[session_id]["conversationHistory"].append({"sender": sender, "text": text})

        sessions[session_id]["turns"] = max(
            sessions[session_id]["turns"] + 1,
            len(sessions[session_id]["conversationHistory"]),
        )
        sessions[session_id]["last_seen_epoch_s"] = int(time.time())
        session_snapshot = sessions[session_id].copy()

    initial_state: HoneypotState = {
        "sessionId": session_id,
        "turns": session_snapshot["turns"],
        "is_scam": False,
        "risk_score": 0.0,
        "risk_signals": session_snapshot.get("risk_signals", []),
        "last_message": text,
        "conversationHistory": session_snapshot["conversationHistory"],
        "extracted_intel": session_snapshot["extracted_intel"],
        "agent_reply": "",
        "stage": session_snapshot.get("stage", "probing"),
    }

    final_state = graph.invoke(initial_state)
    final_state["engagement_duration_seconds"] = max(
        0,
        int(session_snapshot.get("last_seen_epoch_s", int(time.time())))
        - int(session_snapshot.get("started_at_epoch_s", int(time.time()))),
    )

    with sessions_lock:
        sessions[session_id]["stage"] = final_state.get("stage", "probing")
        sessions[session_id]["extracted_intel"] = final_state.get("extracted_intel", {})
        sessions[session_id]["risk_signals"] = final_state.get("risk_signals", [])
        finalize_now = should_finalize(final_state, sessions[session_id])
        if finalize_now:
            sessions[session_id]["finalized"] = True

    if finalize_now:
        send_guvi_callback(session_id, final_state)

    normalized_intel = normalize_intelligence(
        final_state.get("extracted_intel", {}),
        final_state.get("risk_signals", []),
    )

    reply = final_state.get("agent_reply")
    if not final_state.get("is_scam"):
        reply = "i will ask my grandson to check and get back to you, thank you for letting me know"
    if not reply:
        reply = "please explain once more i did not understand"

    return {
        "status": "success",
        "reply": reply,
        "risk_score": final_state.get("risk_score", 0.0),
        "signals": final_state.get("risk_signals", []),
        "explanations": explain_scam_decision(final_state.get("risk_signals", [])),
        "extracted_intel": normalized_intel,
    }
