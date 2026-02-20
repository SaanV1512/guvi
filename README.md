# Honeypot API

## Description
A multi-turn scam honeypot API that detects social-engineering attempts, keeps scammers engaged, and extracts actionable intelligence (phone, links, UPI, email, account IDs, references) for final scoring callbacks.

## Tech Stack
- Python, FastAPI, LangGraph
- Regex + spaCy (NLP extraction)
- Groq LLM (`llama-3.1-8b-instant`) for scam semantics, response generation, and extraction cross-check

## Project Structure
```text
.
+-- README.md
+-- requirements.txt
+-- .env.example
+-- main.py                    # entrypoint wrapper
+-- intelligence.py            # compatibility wrapper
+-- src/
¦   +-- __init__.py
¦   +-- main.py                # API route layer
¦   +-- honeypot_agent.py      # graph + stage logic
¦   +-- intelligence.py        # detection/extraction/reply logic
¦   +-- session_store.py       # session state + finalization
¦   +-- config.py              # env config
+-- docs/
    +-- architecture.md
```

## Setup
1. Clone repo and create venv
2. Install dependencies
3. Configure env vars
4. Run API

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

## Environment Variables
Use `.env.example` as template.

## API Endpoint
- URL: `/honeypot`
- Method: `POST`
- Auth: header `x-api-key`

## Approach
- Scam detection: weighted behavioral/rule signals + optional LLM semantic judge.
- Intelligence extraction: regex and NLP seed extraction, then LLM cross-verifies/adds missed items.
- Engagement: stage-aware LLM persona (probing -> extracting -> closing) with anti-leak guardrails.

For architecture details, see `docs/architecture.md`.
