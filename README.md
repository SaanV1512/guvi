# guvi
#test
# Agentic HoneyPot for Scam Detection

## Overview
This project implements an agentic honeypot system that detects scam messages and autonomously engages scammers to extract actionable intelligence without revealing detection.

The system is exposed as a public REST API and uses a state-machine–based architecture to handle multi-turn conversations in a controlled and extensible way.

---

## Core Capabilities
- Scam intent detection with risk scoring
- Autonomous agent engagement
- Multi-turn conversation handling
- Scam intelligence extraction
- Session-based memory
- Public REST API

---

## Architecture
The system is orchestrated using LangGraph, with the following flow:

INGEST → DETECT → (if scam) AGENT → FINAL

- FastAPI handles API requests
- LangGraph manages control flow and state transitions
- intelligence.py contains detection, reasoning, and agent logic

---

## API Endpoint

### POST /honeypot

Accepts incoming messages from a suspected scammer.

Example Request:
{
  "sessionId": "abc123",
  "message": {
    "sender": "scammer",
    "text": "Your bank account will be blocked today. Verify immediately.",
    "timestamp": 1770005528731
  }
}

Example Response:
{
  "status": "success",
  "reply": "Please explain what I need to do",
  "risk_score": 0.82,
  "signals": ["urgency", "threat"],
  "extracted_intel": {}
}

---

## State Management
Each request updates a shared session state containing:
- conversation history
- turn count
- scam risk indicators
- extracted intelligence
- agent response

This state flows through the LangGraph nodes.

---

## Ethics & Safety
- No impersonation of real individuals
- No illegal or harmful instructions
- Intelligence extraction limited to scam indicators
- Responsible data handling

---

## Local Setup

python3 -m venv .venv
source .venv/bin/activate
pip install fastapi uvicorn langgraph groq requests
uvicorn main:app --reload

---

## Project Status
- Architecture and orchestration complete
- Agent engagement integrated
- Intelligence logic under iteration
- Final evaluation callback pending

---

## Team Roles
- Systems / Architecture: API, orchestration, sessions, callbacks
- Intelligence / Reasoning: Detection logic, agent behavior, extraction