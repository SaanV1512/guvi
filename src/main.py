import time
from typing import Any, Dict

import requests
from fastapi import FastAPI, Header, HTTPException

from .config import API_KEY, GUVI_CALLBACK_URL
from .honeypot_agent import HoneypotState, normalize_intelligence, run_honeypot_turn
from .session_store import persist_final_state, upsert_and_snapshot_session
from .intelligence import explain_scam_decision


app = FastAPI(title="Agentic Honeypot API", version="2.1.0")


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

    session_snapshot = upsert_and_snapshot_session(
        session_id=session_id,
        metadata=payload.get("metadata", {}),
        incoming_history=incoming_history,
        sender=sender,
        text=text,
    )

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

    final_state = run_honeypot_turn(initial_state)
    final_state["engagement_duration_seconds"] = max(
        0,
        int(session_snapshot.get("last_seen_epoch_s", int(time.time())))
        - int(session_snapshot.get("started_at_epoch_s", int(time.time()))),
    )

    finalize_now = persist_final_state(session_id, final_state)
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
