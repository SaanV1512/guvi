import time
from threading import Lock
from typing import Any, Dict, List

sessions: Dict[str, Dict[str, Any]] = {}
sessions_lock = Lock()

CANONICAL_INTEL_KEYS = (
    "urls",
    "phones",
    "upis",
    "bankAccounts",
    "emailAddresses",
    "caseIds",
    "orderIds",
    "policyNumbers",
    "organizations",
    "additionalIndicators",
)


def _initialize_session(metadata: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "turns": 0,
        "finalized": False,
        "conversationHistory": [],
        "extracted_intel": {key: [] for key in CANONICAL_INTEL_KEYS},
        "risk_signals": [],
        "stage": "probing",
        "last_intel_signature": "",
        "stagnant_turns": 0,
        "started_at_epoch_s": int(time.time()),
        "last_seen_epoch_s": int(time.time()),
        "metadata": metadata or {},
    }


def upsert_and_snapshot_session(
    session_id: str,
    metadata: Dict[str, Any],
    incoming_history: List[Dict[str, Any]],
    sender: str,
    text: str,
) -> Dict[str, Any]:
    with sessions_lock:
        if session_id not in sessions:
            sessions[session_id] = _initialize_session(metadata)

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

        if (
            not sessions[session_id]["conversationHistory"]
            or sessions[session_id]["conversationHistory"][-1].get("text") != text
        ):
            sessions[session_id]["conversationHistory"].append({"sender": sender, "text": text})

        sessions[session_id]["turns"] = max(
            sessions[session_id]["turns"] + 1,
            len(sessions[session_id]["conversationHistory"]),
        )
        sessions[session_id]["last_seen_epoch_s"] = int(time.time())
        return sessions[session_id].copy()


def _should_finalize(final_state: Dict[str, Any], session_state: Dict[str, Any]) -> bool:
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
        )
        if intel.get(k)
    )
    turns = int(final_state.get("turns", 0))
    risk = float(final_state.get("risk_score", 0.0))
    stagnant_turns = int(session_state.get("stagnant_turns", 0))

    if final_state.get("is_scam"):
        if turns >= 11 and intel_buckets >= 2 and stagnant_turns >= 2:
            return True
        if final_state.get("stage") == "closing" and turns >= 10 and intel_buckets >= 3 and stagnant_turns >= 1:
            return True
        return False
    return turns >= 3 and risk < 0.3


def persist_final_state(session_id: str, final_state: Dict[str, Any]) -> bool:
    with sessions_lock:
        sessions[session_id]["stage"] = final_state.get("stage", "probing")
        sessions[session_id]["extracted_intel"] = final_state.get("extracted_intel", {})
        sessions[session_id]["risk_signals"] = final_state.get("risk_signals", [])

        intel_now = sessions[session_id]["extracted_intel"]
        signature_parts = []
        for k in (
            "urls",
            "phones",
            "upis",
            "bankAccounts",
            "emailAddresses",
            "caseIds",
            "orderIds",
            "policyNumbers",
        ):
            signature_parts.append(f"{k}:{'|'.join(sorted(intel_now.get(k, [])))}")
        signature = "||".join(signature_parts)

        if signature == sessions[session_id].get("last_intel_signature", ""):
            sessions[session_id]["stagnant_turns"] = int(sessions[session_id].get("stagnant_turns", 0)) + 1
        else:
            sessions[session_id]["stagnant_turns"] = 0
            sessions[session_id]["last_intel_signature"] = signature

        finalize_now = _should_finalize(final_state, sessions[session_id])
        if finalize_now:
            sessions[session_id]["finalized"] = True
        return finalize_now
