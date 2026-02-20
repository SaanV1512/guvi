import json
import os
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

from dotenv import load_dotenv
from groq import Groq

load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
groq_client = Groq(api_key=GROQ_API_KEY) if GROQ_API_KEY else None
ENABLE_NLP_EXTRACTION = os.getenv("ENABLE_NLP_EXTRACTION", "true").lower() == "true"
ENABLE_LLM_EXTRACTION = os.getenv("ENABLE_LLM_EXTRACTION", "true").lower() == "true"

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
EMAIL_REGEX = re.compile(r"(?<![\w.+-])[a-zA-Z0-9._%+\-]{1,64}@[a-zA-Z0-9.\-]{1,253}\.[a-zA-Z]{2,}(?![\w.-])")
CASE_ID_REGEX = re.compile(
    r"\b(?:reference|case|ticket|complaint|ref)\b\s*(?:id|number|no)?\s*(?:is|=|:|#)?\s*([A-Z]{2,}(?:-\d+){1,3}|[A-Z0-9]{5,})\b",
    re.IGNORECASE,
)
ORDER_ID_REGEX = re.compile(
    r"\b(?:order|txn|transaction)\s*(?:id|number|no)?\s*[:#-]?\s*([A-Z0-9][A-Z0-9\-]{3,})\b",
    re.IGNORECASE,
)
POLICY_ID_REGEX = re.compile(
    r"\b(?:policy)\s*(?:id|number|no)?\s*[:#-]?\s*([A-Z0-9][A-Z0-9\-]{3,})\b",
    re.IGNORECASE,
)
ORG_CONTEXT_REGEX = re.compile(
    r"\b(?:from|representing|calling from)\s+([A-Za-z][^,.;\n]{2,36})",
    re.IGNORECASE,
)

SCAM_PATTERNS = {
    "urgency": re.compile(r"\b(urgent|immediately|now|asap|act fast|within \d+ (minutes?|hours?)|right away)\b", re.IGNORECASE),
    "threat": re.compile(r"\b(blocked|suspended|frozen|deactivated|legal action|penalty|court notice|blacklist)\b", re.IGNORECASE),
    "credential": re.compile(r"\b(otp|pin|password|cvv|mpin|verification code|one[- ]time password)\b", re.IGNORECASE),
    "kyc_or_verification": re.compile(r"\b(kyc|verify your account|verification pending|update pan|aadhaar|link aadhaar)\b", re.IGNORECASE),
    "payment_push": re.compile(r"\b(send|transfer|pay|deposit|collect request|scan and pay|approve mandate)\b", re.IGNORECASE),
    "impersonation": re.compile(r"\b(bank|sbi|hdfc|icici|rbi|income tax|customs|police|courier|amazon|flipkart|paytm)\b", re.IGNORECASE),
    "remote_access": re.compile(r"\b(anydesk|teamviewer|quicksupport|remote app|screen share|install app)\b", re.IGNORECASE),
    "phishing": URL_REGEX,
    "upi_request": UPI_REGEX,
    "phone_request": PHONE_REGEX,
    "bank_account": BANK_REGEX,
}

WEIGHTS = {
    "urgency": 0.13,
    "threat": 0.20,
    "credential": 0.32,
    "kyc_or_verification": 0.16,
    "payment_push": 0.24,
    "impersonation": 0.14,
    "remote_access": 0.28,
    "phishing": 0.30,
    "upi_request": 0.23,
    "phone_request": 0.09,
    "bank_account": 0.14,
}

SAFE_DOMAINS = {"google.com", "youtube.com", "microsoft.com", "apple.com", "wikipedia.org", "github.com"}

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

BANK_CONTEXT_REGEX = re.compile(r"\b(my account|account number|a/c no|ifsc|beneficiary|transfer to|send to this account)\b", re.IGNORECASE)
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
    out: List[str] = []
    for m in history:
        t = str(m.get("text", "")).strip()
        if t:
            out.append(t)
    return out


def _normalize_identifier(raw: str) -> str:
    return re.sub(r"\s+", "", raw.strip().upper())


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


def _clean_org_name(raw: str) -> str:
    value = (raw or "").strip()
    value = re.sub(r"^\s*the\s+", "", value, flags=re.IGNORECASE)
    value = re.split(r"\b(employee id|otp|account|reference|case id|phone|number)\b", value, flags=re.IGNORECASE)[0]
    value = re.split(r"\b(to stop|to secure|to verify|please|send|share|now)\b", value, flags=re.IGNORECASE)[0]
    words = value.split()
    if len(words) > 6:
        value = " ".join(words[:6])
    return value.strip(" ,.-")


def _is_valid_organization(name: str) -> bool:
    n = (name or "").strip()
    if len(n) < 3:
        return False
    low = n.lower()
    banned = ["verification page", "within the next", "right away", "immediately", "send otp", "account number", "otp", "link"]
    if any(b in low for b in banned):
        return False
    if re.search(r"^\d+$", n):
        return False
    return True


def _extract_artifacts(text: str) -> Dict[str, List[str]]:
    urls = []
    for m in URL_REGEX.findall(text or ""):
        u = _normalize_url(m)
        if u:
            urls.append(u)

    phones = []
    for m in PHONE_REGEX.findall(text or ""):
        p = _normalize_phone(m)
        if p:
            phones.append(p)

    upis = [m.group(0).lower() for m in UPI_REGEX.finditer(text or "")]
    emails = [m.group(0).lower() for m in EMAIL_REGEX.finditer(text or "")]

    bank_candidates = BANK_REGEX.findall(text or "")
    has_bank_context = bool(BANK_CONTEXT_REGEX.search(text or "") or IFSC_REGEX.search(text or ""))
    bank_accounts = [x for x in bank_candidates if has_bank_context and len(x) >= 12]

    case_ids = [_normalize_identifier(m.group(1)) for m in CASE_ID_REGEX.finditer(text or "")]
    order_ids = [_normalize_identifier(m.group(1)) for m in ORDER_ID_REGEX.finditer(text or "")]
    policy_numbers = [_normalize_identifier(m.group(1)) for m in POLICY_ID_REGEX.finditer(text or "")]
    organizations = [_clean_org_name(m.group(1)) for m in ORG_CONTEXT_REGEX.finditer(text or "")]
    organizations = [o for o in organizations if _is_valid_organization(o)]

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
        "additionalIndicators": [],
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
        "additionalIndicators": [],
    }
    if _nlp is None or not text:
        return out

    doc = _nlp(text)
    for ent in doc.ents:
        val = ent.text.strip()
        if ent.label_ == "UPI_ID" and UPI_REGEX.match(val):
            out["upis"].append(val.lower())
        elif ent.label_ == "PHONE":
            p = _normalize_phone(val)
            if p:
                out["phones"].append(p)
        elif ent.label_ == "BANK_ACCOUNT" and BANK_REGEX.match(val):
            out["bankAccounts"].append(val)
        elif ent.label_ == "CASE_ID":
            out["caseIds"].append(_normalize_identifier(val.split()[-1]))
        elif ent.label_ == "ORDER_ID":
            out["orderIds"].append(_normalize_identifier(val.split()[-1]))
        elif ent.label_ == "POLICY_ID":
            out["policyNumbers"].append(_normalize_identifier(val.split()[-1]))

    for k in out:
        out[k] = list(dict.fromkeys(out[k]))
    return out


def _merge_artifacts(a: Dict[str, List[str]], b: Dict[str, List[str]]) -> Dict[str, List[str]]:
    merged = {}
    for key in set(a.keys()) | set(b.keys()):
        merged[key] = list(dict.fromkeys((a.get(key, []) or []) + (b.get(key, []) or [])))
    return merged


def _normalize_extracted_payload(payload: Dict[str, Any]) -> Dict[str, List[str]]:
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
        "additionalIndicators": [],
    }
    if not payload:
        return out

    def ensure_list(v: Any) -> List[str]:
        if isinstance(v, list):
            return [str(x).strip() for x in v if str(x).strip()]
        if isinstance(v, str) and v.strip():
            return [v.strip()]
        return []

    key_map = {
        "urls": "urls",
        "phishingLinks": "urls",
        "phones": "phones",
        "phoneNumbers": "phones",
        "upis": "upis",
        "upiIds": "upis",
        "bankAccounts": "bankAccounts",
        "emailAddresses": "emailAddresses",
        "caseIds": "caseIds",
        "orderIds": "orderIds",
        "policyNumbers": "policyNumbers",
        "organizations": "organizations",
        "contactNames": "additionalIndicators",
        "additionalIndicators": "additionalIndicators",
    }

    for sk, tk in key_map.items():
        for value in ensure_list(payload.get(sk)):
            if tk == "phones":
                p = _normalize_phone(value)
                if p:
                    out[tk].append(p)
            elif tk == "urls":
                if "@" in value and not value.lower().startswith(("http://", "https://")):
                    continue
                u = _normalize_url(value)
                if u:
                    out[tk].append(u)
            elif tk == "upis":
                if UPI_REGEX.search(value):
                    out[tk].append(value.lower())
            elif tk in {"caseIds", "orderIds", "policyNumbers"}:
                nid = _normalize_identifier(value)
                if tk == "caseIds" and (re.fullmatch(r"\d{1,6}", nid) or nid in {"RIGHT", "NOW", "IMMEDIATELY", "URGENT"}):
                    continue
                if tk == "policyNumbers" and (re.fullmatch(r"\d+", nid) or not re.search(r"[A-Z]", nid)):
                    continue
                out[tk].append(nid)
            elif tk == "organizations":
                org = _clean_org_name(value)
                if _is_valid_organization(org):
                    out[tk].append(org)
            elif tk == "additionalIndicators":
                if len(value.strip()) >= 3:
                    out[tk].append(value.strip())
            elif tk == "emailAddresses":
                if EMAIL_REGEX.search(value):
                    out[tk].append(value.lower())
            elif tk == "bankAccounts":
                digits = re.sub(r"\D", "", value)
                if 12 <= len(digits) <= 18:
                    out[tk].append(digits)

    for k in out:
        out[k] = list(dict.fromkeys(out[k]))
    return out


def _llm_extract_artifacts(
    message: str,
    history: Optional[Sequence[Dict[str, Any]]] = None,
    seeded_extracted: Optional[Dict[str, List[str]]] = None,
) -> Dict[str, List[str]]:
    empty = {
        "urls": [],
        "phones": [],
        "upis": [],
        "bankAccounts": [],
        "emailAddresses": [],
        "caseIds": [],
        "orderIds": [],
        "policyNumbers": [],
        "organizations": [],
        "additionalIndicators": [],
    }
    if not (ENABLE_LLM_EXTRACTION and groq_client):
        return empty

    history_text = "\n".join(_extract_texts(history)[-8:])
    seed_text = json.dumps(seeded_extracted or {}, ensure_ascii=True)
    prompt = f"""
You are validating and improving an extraction result.
Extract only explicitly mentioned scammer-side intelligence from this conversation.
Return strict JSON object with exactly these keys:
urls, phones, upis, bankAccounts, emailAddresses, caseIds, orderIds, policyNumbers, organizations, additionalIndicators
Each value must be an array of strings.
Do not infer. Keep only explicit values. Remove noisy/wrong items.
Use additionalIndicators for explicit identifiers not covered by schema (names, aliases, handles, employee ids, addresses).

Seeded extraction:
{seed_text}

History:
{history_text}

Latest message:
{message}
"""
    try:
        resp = groq_client.chat.completions.create(
            model="llama-3.1-8b-instant",
            temperature=0.0,
            max_tokens=260,
            messages=[
                {"role": "system", "content": "You are an information extractor. Output JSON only."},
                {"role": "user", "content": prompt},
            ],
        )
        content = (resp.choices[0].message.content or "").strip()
        start = content.find("{")
        end = content.rfind("}")
        if start == -1 or end == -1 or end <= start:
            return empty
        parsed = json.loads(content[start : end + 1])
        return _normalize_extracted_payload(parsed if isinstance(parsed, dict) else {})
    except Exception:
        return empty


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
        "additionalIndicators",
    ):
        intel_store.setdefault(key, [])

    extracted = _extract_artifacts(message or "")
    extracted = _merge_artifacts(extracted, _nlp_extract_artifacts(message or ""))
    llm_verified = _llm_extract_artifacts(message or "", history, seeded_extracted=extracted)
    extracted = _merge_artifacts(extracted, llm_verified)

    if history:
        for h in history[-30:]:
            h_text = str(h.get("text", ""))
            if not h_text.strip():
                continue
            extra = _extract_artifacts(h_text)
            extra = _merge_artifacts(extra, _nlp_extract_artifacts(h_text))

            sender = str(h.get("sender", "")).lower().strip()
            if sender and sender not in {"scammer", "attacker", "fraudster"}:
                extra["organizations"] = []

            for k in extracted:
                extracted[k].extend(extra[k])

    sanitized = _normalize_extracted_payload(extracted)
    for k in extracted.keys():
        if k in sanitized:
            extracted[k] = sanitized[k]

    for key in extracted:
        cleaned = list(dict.fromkeys(extracted[key]))
        for item in cleaned:
            if item not in intel_store[key]:
                intel_store[key].append(item)

    return intel_store


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
    return [MESSAGE_EXPLANATIONS.get(s, f"Detected {s} indicator") for s in signals]


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


def _infer_stage_from_prompt(persona_prompt: str) -> str:
    p = (persona_prompt or "").lower()
    if "current engagement stage: closing" in p:
        return "closing"
    if "current engagement stage: extracting" in p:
        return "extracting"
    return "probing"


def _sanitize_reply(reply: str) -> str:
    if not reply:
        return ""
    text = re.sub(r"\s+", " ", reply.strip())
    text = re.sub(r"\b(my otp is|otp is|pin is|cvv is)\b.*", "i cannot share otp or pin here", text, flags=re.IGNORECASE)
    text = re.sub(r"\b(hang up|on call|call disconnected)\b", "end this chat", text, flags=re.IGNORECASE)
    text = re.sub(r"\b(do not proceed|for your safety)\b", "i will verify this myself", text, flags=re.IGNORECASE)
    return text[:220].strip()


def _is_investigative_reply(text: str) -> bool:
    t = (text or "").lower()
    if "?" in t:
        return True
    probe_terms = ["company", "website", "reference", "case id", "number", "email", "upi", "ifsc", "account"]
    return any(term in t for term in probe_terms)


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


def _choose_target_question(
    stage: str,
    intel_store: Dict[str, List[str]],
    latest_message: str,
    risk_signals: Optional[Sequence[str]] = None,
) -> str:
    text = (latest_message or "").lower()
    risk_signals = list(risk_signals or [])

    if not intel_store.get("phones"):
        return "i am worried and confused can you share your callback number once more"
    if not intel_store.get("urls"):
        return "link not opening in my phone can you send full website again"
    if not intel_store.get("emailAddresses"):
        return "i am not able to call properly from my phone can you share support email also"
    if not intel_store.get("upis") and ("upi" in text or "pay" in text or "transfer" in text):
        return "which upi id exactly should i send to can you type slowly"
    if not intel_store.get("bankAccounts") and ("account" in text or "ifsc" in text):
        return "bank transfer option asks account number and ifsc can you share both"
    if not intel_store.get("caseIds") and ("case" in text or "reference" in text or "ticket" in text):
        return "please send case id again i want to note it correctly"

    if "credential" in risk_signals:
        return "otp came but i am confused where to enter it can you guide step by step"
    if "urgency" in risk_signals or "threat" in risk_signals:
        return "okay okay i am doing now just tell me exact next step slowly"

    if stage == "closing":
        return "i am trying and writing everything i will verify and get back shortly"
    return "i am worried can you repeat your support details once"


def generate_agent_reply(
    persona_prompt: str,
    conversation_history: Sequence[Dict[str, Any]],
    latest_message: str,
    intel_store: Dict[str, List[str]],
    risk_signals: Optional[Sequence[str]] = None,
) -> str:
    stage = _infer_stage_from_prompt(persona_prompt)
    fallback = _choose_target_question(stage, intel_store or {}, latest_message or "", risk_signals or [])

    history_text = "\n".join([f"{m.get('sender', 'unknown')}: {m.get('text', '')}" for m in (conversation_history or [])[-8:]])
    system_prompt = f"""
{persona_prompt}

You are in a controlled honeypot text chat with a scammer.
Objective:
1) Keep scammer engaged naturally.
2) Extract missing actionable intelligence (phone, UPI, URL, bank details, email, reference ids).
3) Never provide OTP/PIN/password/card/cvv.
4) If stage is closing, politely disengage naturally but you may ask at most one soft final question.
5) Sound worried and cooperative, not accusatory.
6) This is text chat; avoid call-script words like hang up, line disconnected.

Current extracted intelligence:
{intel_store}

Recent conversation:
{history_text}

Style:
- One short message.
- Natural worried older-person tone.
- Ask one focused question unless closing.
"""

    llm_reply = _call_groq_for_reply(system_prompt, latest_message or "")
    if llm_reply:
        cleaned = _sanitize_reply(llm_reply)
        if stage != "closing" and not _is_investigative_reply(cleaned):
            return _sanitize_reply(fallback)
        if cleaned:
            return cleaned
    return _sanitize_reply(fallback) or "please explain again i am not understanding"
