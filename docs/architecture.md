# Architecture

## Runtime Flow
1. `POST /honeypot` enters `src/main.py`
2. Session state is updated in `src/session_store.py`
3. LangGraph pipeline in `src/honeypot_agent.py` runs:
   - `INGEST`
   - `DETECT` (risk + scam decision)
   - `AGENT` (extract intelligence + generate reply)
   - `FINAL`
4. State is persisted and callback is sent when finalize conditions are met.

## Modules
- `src/main.py`: FastAPI endpoint, request validation, API response, callback trigger.
- `src/honeypot_agent.py`: graph orchestration, stage progression, intelligence normalization.
- `src/intelligence.py`: detection signals, regex/NLP extraction, LLM extraction cross-check, persona reply generation.
- `src/session_store.py`: in-memory session tracking, stagnation tracking, finalize gating.
- `src/config.py`: environment-driven config (`API_KEY`, callback URL).

## Extraction Strategy
1. Rule-based extraction (regex)
2. NLP extraction (spaCy EntityRuler)
3. LLM cross-verification and augmentation over seeded extraction
4. Sanitization/normalization to keep output usable and scoreable

## Output Contract
Primary response includes `reply` plus useful debugging fields (`risk_score`, `signals`, `extracted_intel`).
Final callback includes `scamDetected`, engagement metrics, and normalized extracted intelligence.
