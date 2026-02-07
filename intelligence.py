from email import message
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
    "phishing": 0.4,
     "phone_request": 0.2,
    "bank_account": 0.2 
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
    
    if re.search(DOMAIN_REGEX, text):
        score += WEIGHTS["phishing"]
        signals.append("phishing")

    score = min(score, 1.0)
    return score, list(set(signals))




def explain_scam_decision(signals):
    return [f"Detected {sig} pattern" for sig in signals]


UPI_REGEX = r'(?<!\w)[a-zA-Z0-9.\-_]{3,}@[a-zA-Z]{2,}(?!\w)'
PHONE_REGEX = r'(?<!\d)(?:\+?91[\-\s]?|0?91[\-\s]?|0)?[6-9]\d{9}(?!\d)'
URL_REGEX = r'https?://[^\s"<>]+|www\.[^\s"<>]+|\b[a-zA-Z0-9-]+\.[a-zA-Z]{2,}\b(?!\w*@\w)'
DOMAIN_REGEX = r'\b[a-zA-Z0-9-]+\.(com|in|net|org|co|io|link)\b'
BANK_REGEX = r'(?<!\d)\d{12,16}(?!\d)'

BANK_CONTEXT_REGEX = r'(send|share|confirm|enter|provide)\s+(your\s+)?(bank\s+)?account'

SCAM_PATTERNS["phishing"] = URL_REGEX
SCAM_PATTERNS["upi_request"] = UPI_REGEX
SCAM_PATTERNS["phone_request"] = PHONE_REGEX
SCAM_PATTERNS["bank_account"] = BANK_REGEX


def extract_bank_accounts_with_context(message: str):
    found_accounts = re.findall(BANK_REGEX, message)
    owns_context = re.search(BANK_CONTEXT_REGEX, message.lower())

    if owns_context:
        return found_accounts
    return []


def normalize_phone(p):
    digits = re.sub(r'\D', '', p)  # remove all non-digits

    # Case 1: 0-91-9876543210 → 0919876543210
    if digits.startswith("091") and len(digits) == 13:
        digits = digits[3:]  # strip 0 + 91

    # Case 2: 91-9876543210 → 919876543210
    elif digits.startswith("91") and len(digits) == 12:
        digits = digits[2:]  # strip 91

    # Case 3: 9876543210 (already local)
    elif len(digits) == 10:
        pass

    else:
        return None  # invalid / unknown format

    return f"+91{digits}"
def normalize_url(u):
    u = u.strip().lower()
    if not u.startswith("http"):
        u = "http://" + u
    return u

def extract_data(message):
    return {
        "urls": re.findall(URL_REGEX, message),
        "phones": re.findall(PHONE_REGEX, message),
        "upis": [m.group(0) for m in re.finditer(UPI_REGEX, message)],
        "bankAccounts": extract_bank_accounts_with_context(message),
    }
def extract_data_from_history(history):
    all_text = " ".join([m["text"] for m in history])
    return {
        "urls": re.findall(URL_REGEX, all_text),
        "phones": re.findall(PHONE_REGEX, all_text),
        "upis": [m.group(0) for m in re.finditer(UPI_REGEX, all_text)],
        "bankAccounts": extract_bank_accounts_with_context(all_text)
    }
def is_valid_url(u: str) -> bool:
    return bool(re.match(URL_REGEX, u))

def update_intelligence(intel_store: dict, message: str, history=None):

    extracted = extract_data(message)
    hist_extracted = extract_data_from_history(history) if history else {}

    combined = {}
    for k in set(extracted.keys()).union(hist_extracted.keys()):
        combined[k] = []
        combined[k].extend(extracted.get(k, []))
        combined[k].extend(hist_extracted.get(k, []))

    for k, v in combined.items():
        intel_store.setdefault(k, [])

        for item in v:
            if k == "phones":
                item = normalize_phone(item)
                if not item:
                    continue

            if k == "urls":
                if not is_valid_url(item):
                    continue
                item = normalize_url(item)

            if item not in intel_store[k]:
                intel_store[k].append(item)

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
- Be curious but bit vulnerable
- Ask questions that expose scammer details
- Never actually provide OTP, PIN, or sensitive info.
- Try to extract more details from the scammer which they haven't revealed yet by saying things like "Cant call the number you gave me, can you share the link instead?" or "I am not able to find that UPI ID on my phone, can you please tell me your bank details instead?".
- Occasionally pretend you didn’t understand and ask them to repeat details.
"""

    return call_groq(system_prompt, latest_message)