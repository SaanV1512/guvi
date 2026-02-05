import re
import random
from groq import Groq
from dotenv import load_dotenv
import os
import requests


load_dotenv()
groq_client = Groq(api_key=os.environ.get("GROQ_API_KEY"))

SCAM_PATTERNS = {
    "urgency": r"\b(urgent|immediately|now|act fast|limited time)\b",
    "threat": r"\b(blocked|suspended|closed|legal action)\b",
    "credential": r"\b(otp|pin|password|cvv|code)\b",
    "upi_request": r'\b[a-zA-Z0-9.\-_]{3,}@(okhdfcbank|okicici|oksbi|upi|paytm)\b',
    "phishing": r"https?://\S+|www\.\S+",
}

WEIGHTS = {
    "urgency": 0.2,
    "threat": 0.3,
    "credential": 0.3,
    "upi_request": 0.2,
    "phishing": 0.4
}

def llm_scam_judge(message):
    prompt = f"""
    Classify the following message as scam or not-scam.
    Return only one word: SCAM or NOT_SCAM.

    Message:
    "{message}"
    """
    try:
        resp = groq_client.chat.completions.create(
            messages=[
                {"role": "system", "content": "You are a scam detection classifier."},
                {"role": "user", "content": prompt}
            ],
            model="llama-3.1-8b-instant",
            temperature=0.0,
            max_tokens=5
        )
        return "SCAM" in resp.choices[0].message.content.upper()
    except:
        return False



def detect_scam_with_score(message: str, history=None):
    text = message.lower()

    if history:
        history_text = " ".join([m["text"].lower() for m in history])
        text = history_text + " " + text

    score = 0.0
    signals = []

    for key, pattern in SCAM_PATTERNS.items():
        if re.search(pattern, text):
            score += WEIGHTS[key]
            signals.append(key)

    score = min(score, 1.0)
    return score, list(set(signals))




def explain_scam_decision(signals):
    return [f"Detected {sig} pattern" for sig in signals]

UPI_REGEX = r'\b[a-zA-Z0-9.\-_]{3,}@(?(?:okhdfcbank|okicici|oksbi|upi|paytm))\b'
PHONE_REGEX = r'\+91[\-\s]?[6-9]\d{9}|[6-9]\d{9}'
URL_REGEX = r'https?://\S+|www\.\S+'

def extract_data(message):
    return {
        "urls": re.finditer(URL_REGEX, message),
        "phones": re.findall(PHONE_REGEX, message),
        "upis": re.findall(UPI_REGEX, message),
        "otp_requests": bool(re.search(r'\b(otp|code|pin)\b', message, re.IGNORECASE)),
        "urgency": bool(re.search(r'\b(urgent|immediately|now)\b', message, re.IGNORECASE))
    }


def update_intelligence(intel_store: dict, message: str):
    extracted = extract_data(message)

    for k, v in extracted.items():
        if k not in intel_store:
            intel_store[k] = []

        if isinstance(v, list):
            for item in v:
                if item not in intel_store[k]:
                    intel_store[k].append(item)
        else:
            if v and v not in intel_store[k]:
                intel_store[k].append(v)

    return intel_store


def call_groq(system_prompt, user_message):
    try:
        chat_completion = groq_client.chat.completions.create(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message}
            ],
            model="llama-3.1-8b-instant",
            temperature=0.7,
            max_tokens=120
        )
        content = chat_completion.choices[0].message.content
        return content.strip() if content else "Sir I am not understanding please explain"
    except Exception as e:
        print("Groq error:", e)
        return "Sir my account is blocked what should I do now"



def generate_agent_reply(persona_prompt, conversation_history, latest_message, intel_store):
    history_text = "\n".join(
        [f"{m['sender']}: {m['text']}" for m in conversation_history]
    )

    system_prompt = f"""
{persona_prompt}

You are in a honeypot conversation with a scammer.
Your goal is to subtly extract:
- UPI IDs
- Phone numbers
- Links
- Scam method details

Known extracted intelligence so far:
{intel_store}

Conversation so far:
{history_text}

Rules:
- Never reveal you are AI
- Sound human
- Be curious but vulnerable
- Ask questions that expose scammer details
"""

    return call_groq(system_prompt, latest_message)


