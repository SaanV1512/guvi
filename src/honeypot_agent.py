from typing import Any, Dict, List, TypedDict

from langgraph.graph import END, StateGraph

from .intelligence import (
    detect_scam_with_score,
    generate_agent_reply,
    llm_scam_judge,
    update_intelligence,
)


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
        "additionalIndicators": intel_store.get("additionalIndicators", []),
        "suspiciousKeywords": list(dict.fromkeys(risk_signals)),
    }


def compute_stage(intel_store: Dict[str, List[str]], turns: int, current_stage: str) -> str:
    core_buckets = (
        "upis",
        "urls",
        "phones",
        "bankAccounts",
        "emailAddresses",
        "caseIds",
        "orderIds",
        "policyNumbers",
    )
    core_collected = sum(1 for bucket in core_buckets if intel_store.get(bucket))

    if turns >= 9 and core_collected >= 3:
        return "closing"
    if turns >= 10 and core_collected >= 2:
        return "closing"
    if core_collected >= 1 or current_stage == "extracting":
        return "extracting"
    return "probing"


def ingest(state: HoneypotState) -> HoneypotState:
    return state


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


def run_honeypot_turn(initial_state: HoneypotState) -> HoneypotState:
    return graph.invoke(initial_state)
