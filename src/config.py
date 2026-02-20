import os

API_KEY = os.getenv("HONEYPOT_API_KEY", "guvi-secret-key")
GUVI_CALLBACK_URL = os.getenv(
    "GUVI_CALLBACK_URL",
    "https://hackathon.guvi.in/api/updateHoneyPotFinalResult",
)
