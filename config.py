from dotenv import load_dotenv
from os import getenv

load_dotenv()

VIRUS_TOTAL_KEYS: list = [
    getenv("VT_API_KEY1"),
    getenv("VT_API_KEY2"),
    getenv("VT_API_KEY3"),
]
ABUSE_IP_KEYS: list = [
    getenv("AI_API_KEY1"),
    getenv("AI_API_KEY2"),
    getenv("AI_API_KEY3")
]