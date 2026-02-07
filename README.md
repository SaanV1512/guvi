# Agentic AI Honeypot for Scam Detection & Intelligence Extraction

## Problem Statement

Online financial scams (OTP fraud, phishing links, fake bank calls, UPI scams) are increasingly sophisticated and rely on social engineering rather than just malicious links. Traditional spam filters and rule-based detectors fail to capture conversational scam patterns and cannot proactively gather intelligence about scammer infrastructure.

This project builds an **Agentic AI-powered honeypot API** that:
- Detects scam intent from incoming messages in real time
- Engages scammers in a controlled, human-like conversation
- Extracts actionable intelligence (phone numbers, phishing links, UPI IDs, bank accounts)
- Safely disengages once sufficient intelligence is collected
- Exposes everything through a single public API endpoint

Instead of passively classifying messages as scam/not-scam, this system acts as a victim persona (elderly, non-tech-savvy) to keep scammers engaged and extract valuable indicators for threat intelligence feeds, blacklisting, fraud detection models, and law enforcement workflows.

---

## System Architecture

### 1. API Layer (FastAPI)
- Public endpoint: `POST /honeypot`
- Accepts structured message payloads from external systems
- Secured with API key authentication (`X-API-Key` header)
- Handles multiple concurrent sessions with in-memory state management

### 2. Detection Engine (Hybrid Rule-based + LLM)
Hybrid scam detection using:
- **Regex-based heuristics** for:
  - Urgency keywords ("urgent", "blocked", "verify now")
  - Credential requests (OTP, PIN, CVV)
  - UPI ID patterns
  - URLs and phishing domains
  - Phone numbers
  - Bank account numbers
- **Weighted scoring system** to assign a risk score (0.0 to 1.0)
- **LLM classifier fallback** (Groq LLaMA 3.1-8b) for semantic scam detection when rules are inconclusive (risk < 0.4)

### 3. Agentic Honeypot (LLM-driven)
Once a message is flagged as scam:
- An LLM-driven persona (Rajesh, a 65-year-old retired clerk) engages the scammer
- The agent:
  - Acts confused and worried but cooperative
  - Asks naive clarification questions
  - Pretends to struggle with instructions
  - Encourages scammers to repeat phone numbers, links, and payment details
  - Never reveals real OTPs or sensitive information
- Behavior dynamically changes across stages:
  - **Probing**: Confused, asking basic questions
  - **Extracting**: Cooperative, trying to follow instructions
  - **Closing**: Disengaging naturally (e.g., "I will ask my son to help")

### 4. Intelligence Extraction Layer
Structured extraction from conversation:
- **URLs**: Phishing links (normalized to include http://)
- **Phone numbers**: Normalized to +91 format
- **UPI IDs**: Generic pattern support (e.g., abc@upi, xyz@paytm)
- **Bank account numbers**: Only when scammer contextually provides their own details (12-16 digits with context validation)
- Regex + context-aware filters avoid capturing victim's own details

### 5. State Machine (LangGraph)
Conversation managed as a state graph:

```
INGEST → DETECT → [if scam] AGENT → FINAL
                 → [if not scam] FINAL
```

State transitions based on:
- Scam detection results
- Intelligence collected
- Engagement stage (probing → extracting → closing)

### 6. Callback to Evaluation System
Once enough intelligence is collected (closing stage + artifacts present):
- System sends structured result to `https://hackathon.guvi.in/api/updateHoneyPotFinalResult`
- Payload contains:
  - `scamDetected`: Boolean
  - `totalMessagesExchanged`: Turn count
  - `extractedIntelligence`: Normalized intel (bankAccounts, upiIds, phishingLinks, phoneNumbers, suspiciousKeywords)
  - `agentNotes`: Engagement summary

---

## API Documentation

### Endpoint: `POST /honeypot`

**Authentication**: API Key via `X-API-Key` header (value: `guvi-secret-key`)

**Request Body**:
```json
{
  "sessionId": "test-session-123",
  "message": {
    "sender": "scammer",
    "text": "Your account is blocked. Send money to abc@upi urgently or click http://fake.link",
    "timestamp": 1770005528731
  },
  "metadata": {
    "channel": "SMS",
    "language": "English",
    "locale": "IN"
  }
}
```

**Response**:
```json
{
  "status": "success",
  "reply": "oh no my account is blocked? i dont understand what i need to do can you explain again",
  "risk_score": 0.9,
  "signals": ["threat", "upi_request", "phishing"],
  "explanations": [
    "Detected threat pattern",
    "Detected upi_request pattern",
    "Detected phishing pattern"
  ],
  "extracted_intel": {
    "bankAccounts": [],
    "upiIds": ["abc@upi"],
    "phishingLinks": ["http://fake.link"],
    "phoneNumbers": [],
    "suspiciousKeywords": ["threat", "upi_request", "phishing"]
  }
}
```

---

## Key Features

- **Agentic AI honeypot** (not just a classifier)
- **Real-time scam detection** with hybrid rule-based + LLM approach
- **Proactive intelligence extraction** through multi-turn engagement
- **Session-based multi-turn conversations** with in-memory state
- **Dynamic engagement strategy** (probing → extraction → disengage)
- **API-first design** for automated evaluation
- **Stateless per request** (session tracked in memory dictionary)
- **Automatic callback** to evaluation system when intelligence is collected

---

## Detection Patterns

The system detects the following scam indicators:

| Pattern | Regex/Logic | Weight |
|---------|-------------|--------|
| Urgency | `urgent`, `immediately`, `now`, `act fast`, `limited time` | 0.2 |
| Threat | `blocked`, `suspended`, `closed`, `legal action` | 0.3 |
| Credential Request | `otp`, `pin`, `password`, `cvv`, `code` | 0.3 |
| UPI Request | `[a-zA-Z0-9.\-_]{3,}@[a-zA-Z]{2,}` | 0.2 |
| Phishing | URLs and domains | 0.4 |
| Phone Request | Indian phone numbers (10 digits, +91 format) | 0.2 |
| Bank Account | 12-16 digit numbers with context validation | 0.2 |

Risk score is calculated by summing weights of matched patterns (capped at 1.0).

---

## Intelligence Extraction Logic

### Phone Numbers
- Extracts Indian phone numbers in various formats
- Normalizes to `+91XXXXXXXXXX` format
- Handles formats: `0-91-9876543210`, `91-9876543210`, `9876543210`

### UPI IDs
- Extracts patterns like `abc@upi`, `xyz@paytm`, `name@okhdfcbank`
- Validates against common UPI handles

### URLs
- Extracts HTTP/HTTPS URLs and domains
- Normalizes by adding `http://` prefix if missing
- Validates against URL regex pattern

### Bank Accounts
- Extracts 12-16 digit numbers
- Only when scammer provides context (e.g., "send to account", "my account number")
- Avoids capturing victim's own account numbers

---

## Safety & Guardrails

- Agent is explicitly instructed **never to provide OTPs, PINs, or sensitive details**
- Automatic sanitization ensures no accidental leakage of sensitive content
- Links, UPI IDs, and phone numbers are normalized and validated
- Agent disengages naturally after sufficient intelligence is collected
- Context-aware extraction prevents capturing victim's own details
- No impersonation of real individuals
- Intelligence extraction limited to scam indicators

---

## Local Setup

### Prerequisites
- Python 3.8+
- Groq API key (for LLM-based detection and agent replies)

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd <repository-name>
```

2. Create and activate virtual environment:
```bash
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On Linux/Mac:
source .venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Create `.env` file with your Groq API key:
```
GROQ_API_KEY=your_groq_api_key_here
AI_MODE=DEV
```

5. Run the server:
```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Testing the API

```bash
curl -X POST http://localhost:8000/honeypot \
  -H "Content-Type: application/json" \
  -H "X-API-Key: guvi-secret-key" \
  -d '{
    "sessionId": "test-123",
    "message": {
      "sender": "scammer",
      "text": "Your account is blocked. Call 9876543210 urgently.",
      "timestamp": 1770005528731
    }
  }'
```

---

## Use Cases

- **Scam detection platforms**: Real-time scam identification and intelligence gathering
- **Telecom anti-fraud pipelines**: Automated SMS/call scam detection
- **Banking fraud monitoring**: UPI and account-based scam detection
- **Cyber threat intelligence systems**: Collecting scammer infrastructure data
- **Research datasets**: Social engineering attack patterns and techniques

---

## Technical Stack

- **FastAPI**: REST API framework
- **LangGraph**: State machine orchestration for multi-turn conversations
- **Groq (LLaMA 3.1-8b)**: LLM for semantic scam detection and agent replies
- **Python Regex**: Pattern matching for intelligence extraction
- **Requests**: HTTP client for callback integration

---

## Project Structure

```
.
├── main.py              # FastAPI app, LangGraph state machine, API endpoint
├── intelligence.py      # Detection logic, extraction patterns, agent reply generation
├── requirements.txt     # Python dependencies
├── .env                 # Environment variables (Groq API key)
└── README.md           # This file
```

---

## State Flow Details

### HoneypotState Schema
```python
{
    "sessionId": str,           # Unique session identifier
    "turns": int,               # Number of message exchanges
    "is_scam": bool,            # Scam detection result
    "risk_score": float,        # Risk score (0.0 to 1.0)
    "risk_signals": list,       # Detected scam patterns
    "last_message": str,        # Latest incoming message
    "conversationHistory": list, # Full conversation log
    "extracted_intel": dict,    # Collected intelligence
    "agent_reply": str,         # Generated response
    "stage": str                # Engagement stage (probing/extracting/closing)
}
```

### Node Functions
- **INGEST**: Receives and passes through state
- **DETECT**: Runs hybrid detection (rules + LLM), updates risk score and signals
- **AGENT**: Generates persona-based reply, extracts intelligence, updates stage
- **FINAL**: Terminal node, triggers callback if conditions met

### Routing Logic
- If `is_scam == True`: Route to AGENT
- If `is_scam == False`: Route to FINAL

### Callback Trigger Conditions
- Stage is "closing"
- Session not already finalized
- Has artifacts (URLs OR (phones AND upis))

---

## Evaluation Readiness

The API is designed for automated evaluation:
- Publicly accessible endpoint
- API key authentication
- Handles concurrent sessions
- Returns structured JSON responses
- Stable under repeated evaluation calls
- Can run continuously during judge evaluation windows
- Automatic callback integration with evaluation system

---

## Future Enhancements

- Multi-language support (Hindi, Tamil, Telugu)
- Voice call integration
- Advanced LLM reasoning for complex scam patterns
- Database persistence for session state
- Analytics dashboard for intelligence visualization
- Integration with threat intelligence platforms
- Rate limiting and DDoS protection
- Webhook support for custom callbacks

---

## License

This project is developed for the GUVI Hackathon and is intended for educational and research purposes only.

---

## Disclaimer

This system is designed for scam detection and intelligence gathering purposes only. It should be used responsibly and in compliance with applicable laws and regulations. The authors are not responsible for any misuse of this system.