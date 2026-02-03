from fastapi import FastAPI
from typing import Dict, Any, TypedDict
from langgraph.graph import StateGraph, END

sessions = {}
#Langgraph state
class HoneypotState(TypedDict):
    sessionId: str #HoneypotState describes the shape of the dictionary that flows through LangGraph
    turns: int
    is_scam : bool
#Langgraph node functions

def ingest(state:HoneypotState) -> HoneypotState: #This function receives the current state and returns the updated state.
    return state

def detect(state:HoneypotState) -> HoneypotState: 
    return state

def final(state:HoneypotState) -> HoneypotState:
    return state

#Langgraph graph construction
graph_builder = StateGraph(HoneypotState)
graph_builder.add_node("INGEST", ingest)
graph_builder.add_node("DETECT", detect)
graph_builder.add_node("FINAL", final)
graph_builder.set_entry_point("INGEST")
graph_builder.add_edge("INGEST", "DETECT")
graph_builder.add_edge("DETECT", "FINAL")
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
            "active": True
        }
    sessions[session_id]["turns"] += 1

    initial_state: HoneypotState = {
        "sessionId": session_id,
        "turns": sessions[session_id]["turns"],
        "is_scam": False
    }
    final_state = graph.invoke(initial_state)
    return{
        "status":"received",
        "sessionId": final_state["sessionId"],
        "turns": final_state["turns"],
        "is_scam": final_state["is_scam"]
    }
