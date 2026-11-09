"""Detection vocabulary. Brand, TLD, shortener and look-alike data are loaded from
shared_rules.json, generated from the repository's shared/rules.json (npm run build:rules), so the
bot and the extension agree on what counts as brand impersonation. The chat-only word lists stay
here."""

import json
import re
from pathlib import Path

_SHARED = json.loads((Path(__file__).with_name("shared_rules.json")).read_text(encoding="utf-8"))

MONEY_LURES = [
    "gift", "giftcard", "gift card", "free nitro", "nitro", "steam gift", "reward", "prize",
    "giveaway", "airdrop", "claim", "bonus", "voucher", "cashback", "crypto", "wallet", "usdt",
]
MONEY_AMOUNT = re.compile(r"(\$|€|£|usd\s?)\s?\d+|\d+\s?(\$|usd|dollars?|eur)", re.IGNORECASE)

URGENCY = ["now", "quick", "quickly", "hurry", "limited", "expires", "expire", "today only",
           "last chance", "asap", "before it", "only for you", "first come"]

GREETINGS = ["hi", "hello", "hey", "hiya", "yo", "good morning", "good evening", "salam",
             "assalamualaikum", "bhai", "bhaiya", "dear", "chào", "xin chào"]

SHORTENERS = set(_SHARED["linkShorteners"])

SUSPICIOUS_TLDS = set(_SHARED["suspiciousTlds"])

BRANDS = {key: (b["name"], b["domains"]) for key, b in _SHARED["brands"].items()}

MULTI_PART_SUFFIXES = set(_SHARED["multiPartSuffixes"])

LOOKALIKE_MAP = [tuple(pair) for pair in _SHARED["lookalikeMap"]]
