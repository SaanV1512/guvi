import os
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

from dotenv import load_dotenv
from groq import Groq


load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
groq_client = Groq(api_key=GROQ_API_KEY) if GROQ_API_KEY else None
ENABLE_NLP_EXTRACTION = os.getenv("ENABLE_NLP_EXTRACTION", "true").lower() == "true"

try:
    import spacy
    from spacy.pipeline import EntityRuler
except Exception:
    spacy = None
    EntityRuler = None


UPI_REGEX = re.compile(r"(?<!\w)[a-zA-Z0-9.\-_]{3,}@[a-zA-Z]{2,}(?![\w.-])")
PHONE_REGEX = re.compile(r"(?<!\d)(?:\+?91[-\s]?|0?91[-\s]?|0)?[6-9]\d{9}(?!\d)")
URL_REGEX = re.compile(
    r"https?://[^\s\"<>]+|www\.[^\s\"<>]+|\b[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+\b(?!\w*@\w)",
    re.IGNORECASE,
)
BANK_REGEX = re.compile(r"(?<!\d)\d{12,18}(?!\d)")
EMAIL_REGEX = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")
CASE_ID_REGEX = re.compile(r"\b(?:case|ticket|ref|reference|complaint)[-:\s#]*([A-Z0-9]{5,})\b", re.IGNORECASE)
ORDER_ID_REGEX = re.compile(r"\b(?:order|txn|transaction)[-:\s#]*([A-Z0-9]{5,})\b", re.IGNORECASE)
POLICY_ID_REGEX = re.compile(r"\b(?:policy)[-:\s#]*([A-Z0-9]{5,})\b", re.IGNORECASE)
ORG_CONTEXT_REGEX = re.compile(
    r"\b(?:from|representing|calling from)\s+([A-Za-z][^,.;\n]{2,48})",
    re.IGNORECASE,
)


SCAM_PATTERNS = {
    "urgency": re.compile(
        r"\b(urgent|immediately|now|asap|act fast|within \d+ (minutes?|hours?)|right away)\b",
        re.IGNORECASE,
    ),
    "threat": re.compile(
        r"\b(blocked|suspended|frozen|deactivated|legal action|penalty|court notice|blacklist)\b",
        re.IGNORECASE,
    ),
    "credential": re.compile(
        r"\b(otp|pin|password|cvv|mpin|verification code|one[- ]time password)\b",
        re.IGNORECASE,
    ),
    "kyc_or_verification": re.compile(
        r"\b(kyc|verify your account|verification pending|update pan|aadhaar|link aadhaar)\b",
        re.IGNORECASE,
    ),
    "payment_push": re.compile(
        r"\b(send|transfer|pay|deposit|collect request|scan and pay|approve mandate)\b",
        re.IGNORECASE,
    ),
    "impersonation": re.compile(
        r"\b(bank|sbi|hdfc|icici|rbi|income tax|customs|police|courier|amazon|flipkart|paytm)\b",
        re.IGNORECASE,
    ),
    "remote_access": re.compile(
        r"\b(anydesk|teamviewer|quicksupport|remote app|screen share|install app)\b",
        re.IGNORECASE,
    ),
    "phishing": URL_REGEX,
    "upi_request": UPI_REGEX,
    "phone_request": PHONE_REGEX,
    "bank_account": BANK_REGEX,
}


WEIGHTS = {
    "urgency": 0.13,
    "threat": 0.2,
    "credential": 0.32,
    "kyc_or_verification": 0.16,
    "payment_push": 0.24,
    "impersonation": 0.14,
    "remote_access": 0.28,
    "phishing": 0.3,
    "upi_request": 0.23,
    "phone_request": 0.09,
    "bank_account": 0.14,
}


SAFE_DOMAINS = {
    "google.com",
    "youtube.com",
    "microsoft.com",
    "apple.com",
    "wikipedia.org",
    "github.com",
}

MESSAGE_EXPLANATIONS = {
    "urgency": "Urgency language observed",
    "threat": "Threat or account lock language observed",
    "credential": "Sensitive credential request observed",
    "kyc_or_verification": "KYC/verification pretext observed",
    "payment_push": "Payment transfer pressure observed",
    "impersonation": "Authority or brand impersonation cues observed",
    "remote_access": "Remote control app instruction observed",
    "phishing": "Suspicious link/domain observed",
    "upi_request": "UPI payment identifier observed",
    "phone_request": "Phone contact collection observed",
    "bank_account": "Bank account number observed",
}

BANK_CONTEXT_REGEX = re.compile(
    r"\b(my account|account number|a/c no|ifsc|beneficiary|transfer to|send to this account)\b",
    re.IGNORECASE,
)
IFSC_REGEX = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")

_nlp = None
if ENABLE_NLP_EXTRACTION and spacy is not None:
    try:
        _nlp = spacy.blank("en")
        ruler = _nlp.add_pipe("entity_ruler")
        assert isinstance(ruler, EntityRuler)
        patterns = [
            {"label": "UPI_ID", "pattern": [{"TEXT": {"REGEX": r"(?i)^[a-z0-9.\-_]{3,}@[a-z]{2,}$"}}]},
            {"label": "PHONE", "pattern": [{"TEXT": {"REGEX": r"^\+?91[6-9]\d{9}$"}}]},
            {"label": "PHONE", "pattern": [{"TEXT": {"REGEX": r"^[6-9]\d{9}$"}}]},
            {"label": "BANK_ACCOUNT", "pattern": [{"TEXT": {"REGEX": r"^\d{12,18}$"}}]},
            {"label": "IFSC", "pattern": [{"TEXT": {"REGEX": r"^[A-Z]{4}0[A-Z0-9]{6}$"}}]},
            {"label": "CASE_ID", "pattern": [{"LOWER": {"IN": ["case", "ticket", "ref", "reference", "complaint"]}}, {"IS_PUNCT": True, "OP": "?"}, {"TEXT": {"REGEX": r"^[A-Z0-9]{5,}$"}}]},
            {"label": "ORDER_ID", "pattern": [{"LOWER": {"IN": ["order", "txn", "transaction"]}}, {"IS_PUNCT": True, "OP": "?"}, {"TEXT": {"REGEX": r"^[A-Z0-9]{5,}$"}}]},
            {"label": "POLICY_ID", "pattern": [{"LOWER": "policy"}, {"IS_PUNCT": True, "OP": "?"}, {"TEXT": {"REGEX": r"^[A-Z0-9]{5,}$"}}]},
        ]
        ruler.add_patterns(patterns)
    except Exception:
        _nlp = None


def _extract_texts(history: Optional[Sequence[Dict[str, Any]]]) -> List[str]:
    if not history:
        return []
    texts: List[str] = []
    for m in history:
        text = str(m.get("text", "")).strip()
        if text:
            texts.append(text)
    return texts


def _normalize_url(url: str) -> Optional[str]:
    cleaned = url.strip().rstrip(".,;:!?)]}\"'")
    if not cleaned:
        return None
    if not re.match(r"^https?://", cleaned, flags=re.IGNORECASE):
        cleaned = "http://" + cleaned
    return cleaned.lower()


def _normalize_phone(phone: str) -> Optional[str]:
    digits = re.sub(r"\D", "", phone)
    if len(digits) == 10:
        return f"+91{digits}"
    if len(digits) == 12 and digits.startswith("91"):
        return f"+{digits}"
    if len(digits) == 13 and digits.startswith("091"):
        return f"+91{digits[3:]}"
    return None


def _extract_artifacts(text: str) -> Dict[str, List[str]]:
    urls = []
    for match in URL_REGEX.findall(text):
        normalized = _normalize_url(match)
        if normalized:
            urls.append(normalized)

    phones = []
    for match in PHONE_REGEX.findall(text):
        normalized = _normalize_phone(match)
        if normalized:
            phones.append(normalized)

    upis = [m.group(0).lower() for m in UPI_REGEX.finditer(text)]
    emails = [m.group(0).lower() for m in EMAIL_REGEX.finditer(text)]

    bank_candidates = BANK_REGEX.findall(text)
    has_bank_context = bool(BANK_CONTEXT_REGEX.search(text) or IFSC_REGEX.search(text))
    bank_accounts = [x for x in bank_candidates if has_bank_context and len(x) >= 12]
    case_ids = [m.group(1) for m in CASE_ID_REGEX.finditer(text)]
    order_ids = [m.group(1) for m in ORDER_ID_REGEX.finditer(text)]
    policy_numbers = [m.group(1) for m in POLICY_ID_REGEX.finditer(text)]
    organizations = [m.group(1).strip() for m in ORG_CONTEXT_REGEX.finditer(text)]

    return {
        "urls": list(dict.fromkeys(urls)),
        "phones": list(dict.fromkeys(phones)),
        "upis": list(dict.fromkeys(upis)),
        "bankAccounts": list(dict.fromkeys(bank_accounts)),
        "emailAddresses": list(dict.fromkeys(emails)),
        "caseIds": list(dict.fromkeys(case_ids)),
        "orderIds": list(dict.fromkeys(order_ids)),
        "policyNumbers": list(dict.fromkeys(policy_numbers)),
        "organizations": list(dict.fromkeys(organizations)),
    }


def _nlp_extract_artifacts(text: str) -> Dict[str, List[str]]:
    out = {
        "urls": [],
        "phones": [],
        "upis": [],
        "bankAccounts": [],
        "emailAddresses": [],
        "caseIds": [],
        "orderIds": [],
        "policyNumbers": [],
        "organizations": [],
    }
    if _nlp is None or not text:
        return out

    doc = _nlp(text)
    for ent in doc.ents:
        val = ent.text.strip()
        if ent.label_ == "UPI_ID":
            if UPI_REGEX.match(val):
                out["upis"].append(val.lower())
        elif ent.label_ == "PHONE":
            p = _normalize_phone(val)
            if p:
                out["phones"].append(p)
        elif ent.label_ == "BANK_ACCOUNT":
            if BANK_REGEX.match(val):
                out["bankAccounts"].append(val)
        elif ent.label_ == "CASE_ID":
            out["caseIds"].append(val.split()[-1].upper())
        elif ent.label_ == "ORDER_ID":
            out["orderIds"].append(val.split()[-1].upper())
        elif ent.label_ == "POLICY_ID":
            out["policyNumbers"].append(val.split()[-1].upper())

    # NLP token pass for organizations from context cues.
    for m in ORG_CONTEXT_REGEX.finditer(text):
        out["organizations"].append(m.group(1).strip())

    for k in out:
        out[k] = list(dict.fromkeys(out[k]))
    return out


def _merge_artifacts(base: Dict[str, List[str]], extra: Dict[str, List[str]]) -> Dict[str, List[str]]:
    merged = {}
    for key in set(base.keys()) | set(extra.keys()):
        merged[key] = list(dict.fromkeys((base.get(key, []) or []) + (extra.get(key, []) or [])))
    return merged


def detect_scam_with_score(
    message: str,
    history: Optional[Sequence[Dict[str, Any]]] = None,
) -> Tuple[float, List[str]]:
    message = message or ""
    message_lower = message.lower()
    score = 0.0
    signals: List[str] = []

    for label, pattern in SCAM_PATTERNS.items():
        if pattern.search(message):
            score += WEIGHTS[label]
            signals.append(label)

    history_text = " ".join(_extract_texts(history)).lower()
    if history_text:
        if "otp" in history_text and re.search(r"\bshare|tell|send\b", history_text):
            score += 0.22
            signals.append("credential")
        if re.search(r"\bclick\b", history_text) and re.search(r"\blink\b", history_text):
            score += 0.18
            signals.append("phishing")
        if re.search(r"\btransfer|pay|send money\b", history_text):
            score += 0.16
            signals.append("payment_push")

    if ("bank" in message_lower or "upi" in message_lower) and ("verify" in message_lower or "blocked" in message_lower):
        score += 0.15
        signals.append("impersonation")

    domain_hits = [m.group(0).lower() for m in URL_REGEX.finditer(message)]
    suspicious_domain_hit = False
    for d in domain_hits:
        d_clean = d.replace("http://", "").replace("https://", "").split("/")[0]
        if d_clean and d_clean not in SAFE_DOMAINS:
            suspicious_domain_hit = True
            break
    if suspicious_domain_hit:
        score += 0.12
        signals.append("phishing")

    score = min(score, 1.0)
    return score, list(dict.fromkeys(signals))


def explain_scam_decision(signals: Sequence[str]) -> List[str]:
    explanations = []
    for s in signals:
        explanations.append(MESSAGE_EXPLANATIONS.get(s, f"Detected {s} indicator"))
    return explanations


def llm_scam_judge(message: str, history: Optional[Sequence[Dict[str, Any]]] = None) -> bool:
    if not groq_client:
        return False

    history_text = "\n".join(_extract_texts(history)[-6:])
    prompt = f"""
You classify incoming conversation snippets into SCAM or NOT_SCAM.
Be strict about social engineering signs: urgency, impersonation, credential asks, payment pushes, malicious links.
Return exactly one token: SCAM or NOT_SCAM.

History:
{history_text}

Latest message:
{message}
"""
    try:
        resp = groq_client.chat.completions.create(
            model="llama-3.1-8b-instant",
            temperature=0.0,
            max_tokens=4,
            messages=[
                {"role": "system", "content": "You are a scam classifier for bank and payment fraud chats."},
                {"role": "user", "content": prompt},
            ],
        )
        verdict = (resp.choices[0].message.content or "").strip().upper()
        return verdict.startswith("SCAM")
    except Exception:
        return False


def update_intelligence(
    intel_store: Dict[str, List[str]],
    message: str,
    history: Optional[Sequence[Dict[str, Any]]] = None,
) -> Dict[str, List[str]]:
    intel_store = intel_store or {}
    for key in (
        "urls",
        "phones",
        "upis",
        "bankAccounts",
        "emailAddresses",
        "caseIds",
        "orderIds",
        "policyNumbers",
        "organizations",
    ):
        intel_store.setdefault(key, [])

    extracted = _extract_artifacts(message or "")
    extracted = _merge_artifacts(extracted, _nlp_extract_artifacts(message or ""))

    if history:
        for h in history[-8:]:
            sender = str(h.get("sender", "")).lower()
            if sender and sender not in {"scammer", "attacker", "fraudster"}:
                continue
            h_text = str(h.get("text", ""))
            extra = _extract_artifacts(h_text)
            extra = _merge_artifacts(extra, _nlp_extract_artifacts(h_text))
            for k in extracted:
                extracted[k].extend(extra[k])

    for key in extracted:
        cleaned = list(dict.fromkeys(extracted[key]))
        for item in cleaned:
            if item not in intel_store[key]:
                intel_store[key].append(item)

    return intel_store


def _infer_stage_from_prompt(persona_prompt: str) -> str:
    lowered = (persona_prompt or "").lower()
    if "current engagement stage: closing" in lowered:
        return "closing"
    if "current engagement stage: extracting" in lowered:
        return "extracting"
    return "probing"


INVESTIGATIVE_QUESTION_BANK = [
    "which exact company are you from and your full department name",
    "please share your employee id and official designation",
    "what is your office address and branch location",
    "which official website should i verify now please send full url",
    "what is your callback number with country code",
    "please share case id or complaint reference number again",
]


def _extract_user_questions(conversation_history: Sequence[Dict[str, Any]]) -> str:
    user_text = []
    for msg in conversation_history or []:
        sender = str(msg.get("sender", "")).lower()
        if sender in {"user", "victim", "customer", "honeypot"}:
            user_text.append(str(msg.get("text", "")).lower())
    return " ".join(user_text)


def _next_investigative_question(conversation_history: Sequence[Dict[str, Any]]) -> str:
    asked_text = _extract_user_questions(conversation_history)
    for question in INVESTIGATIVE_QUESTION_BANK:
        probe = question.split(" and ")[0]
        if probe not in asked_text:
            return question
    return "can you share your official website and support number once"


def _choose_target_question(
    stage: str,
    intel_store: Dict[str, List[str]],
    latest_message: str,
    conversation_history: Sequence[Dict[str, Any]],
    risk_signals: Optional[Sequence[str]] = None,
) -> str:
    urls = intel_store.get("urls", [])
    phones = intel_store.get("phones", [])
    upis = intel_store.get("upis", [])
    banks = intel_store.get("bankAccounts", [])
    emails = intel_store.get("emailAddresses", [])
    case_ids = intel_store.get("caseIds", [])
    text = (latest_message or "").lower()
    risk_signals = list(risk_signals or [])

    if stage == "closing":
        return "ok i will check with my son and visit branch later thank you"

    if not phones and "call" in text:
        return "i am not able to note number properly please share full mobile number once"
    if not urls and ("click" in text or "link" in text):
        return "link not opening in my phone can you send full website again"
    if not upis and ("pay" in text or "transfer" in text or "upi" in text):
        return "which upi id exactly should i send to can you type slowly"
    if not banks and ("account" in text or "ifsc" in text or "neft" in text):
        return "bank transfer option asks account number and ifsc can you share both"
    if not emails and ("mail" in text or "email" in text or "support" in text):
        return "can you share your official email so my son can verify"
    if not case_ids and ("case" in text or "ticket" in text or "complaint" in text or "reference" in text):
        return "please send case id again i want to note it correctly"

    if "credential" in risk_signals:
        return "why are you asking otp if you are bank side please explain"
    if "urgency" in risk_signals or "threat" in risk_signals:
        return "you are saying urgent and blocked can you explain reason clearly"

    if stage == "probing":
        return _next_investigative_question(conversation_history)

    return f"i am trying but confused { _next_investigative_question(conversation_history) }"


def _sanitize_reply(reply: str) -> str:
    if not reply:
        return ""
    text = reply.strip()
    text = re.sub(r"\b(my otp is|otp is|pin is|cvv is)\b.*", "i cannot share otp or pin here", text, flags=re.IGNORECASE)
    return text[:280]


def _call_groq_for_reply(system_prompt: str, latest_message: str) -> Optional[str]:
    if not groq_client:
        return None
    try:
        chat_completion = groq_client.chat.completions.create(
            model="llama-3.1-8b-instant",
            temperature=0.65,
            max_tokens=110,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": latest_message},
            ],
        )
        content = chat_completion.choices[0].message.content or ""
        return content.strip() or None
    except Exception:
        return None


def generate_agent_reply(
    persona_prompt: str,
    conversation_history: Sequence[Dict[str, Any]],
    latest_message: str,
    intel_store: Dict[str, List[str]],
    risk_signals: Optional[Sequence[str]] = None,
) -> str:
    stage = _infer_stage_from_prompt(persona_prompt)
    fallback = _choose_target_question(
        stage=stage,
        intel_store=intel_store or {},
        latest_message=latest_message or "",
        conversation_history=conversation_history or [],
        risk_signals=risk_signals or [],
    )

    history_text = "\n".join(
        [f"{m.get('sender', 'unknown')}: {m.get('text', '')}" for m in (conversation_history or [])[-8:]]
    )
    system_prompt = f"""
{persona_prompt}

You are in a controlled honeypot chat with a scammer.
Objective:
1) Keep scammer engaged naturally.
2) Extract missing actionable intelligence (phone, UPI, URL, bank details).
3) Never provide real credentials or money.

Current extracted intelligence:
{intel_store}

Recent conversation:
{history_text}

Style rules:
- Reply in one short message.
- Sound like a worried older person around 60 - 65 years of age.
- Ask at least one focused investigative question but pretend like you are falling for his scam unless stage is closing.
- Prefer questions on identity, company, website, address, employee id, reference id, callback number.
- If scam pressure appears (OTP/urgent/block/payment), mention one red-flag concern in simple words but dont sound like you are accusing the other person of anything, just worried and only mention it once not after every reply, you should sound convinced after the person has reassured you.
- Do not repeat all details already captured.
- If stage is closing, politely disengage.
"""
    llm_reply = _call_groq_for_reply(system_prompt, latest_message or "")
    if llm_reply:
        return _sanitize_reply(llm_reply)
    return _sanitize_reply(fallback) or "please explain again i am not understanding"
