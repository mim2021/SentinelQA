"""Single-message anomaly scoring: explainable heuristics, each signal with its own points.

The target pattern comes from the incident this project is based on: a *trusted* account,
taken over, sends a short, greeting-less message with a money lure and an external link."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from . import rules
from .models import Reason

URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"'`]+", re.IGNORECASE)
# Bare domains like "steamcommunnity.com/gift" that chat clients still auto-link.
# Masked links: Discord "[label](url)" markdown; the Slack adapter rewrites "<url|label>" to the same form.
MASKED_RE = re.compile(r"\[([^\]\n]+)\]\((https?://[^)\s]+)\)", re.IGNORECASE)
BARE_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/[^\s<>\"'`]*)?", re.IGNORECASE)


def _word_re(words: list[str]) -> re.Pattern:
    return re.compile(r"(?<![a-z])(" + "|".join(re.escape(w) for w in words) + r")(?![a-z])", re.IGNORECASE)


MONEY_RE = _word_re(rules.MONEY_LURES)
URGENCY_RE = _word_re(rules.URGENCY)
GREETING_RE = re.compile(r"^\W*(" + "|".join(re.escape(g) for g in rules.GREETINGS) + r")(?![a-z])", re.IGNORECASE)


def extract_links(text: str) -> list[str]:
    links = [m.rstrip(".,;:!?)]>") for m in URL_RE.findall(text)]
    stripped = URL_RE.sub(" ", text)
    for m in BARE_DOMAIN_RE.findall(stripped):
        candidate = m.rstrip(".,;:!?)]>")
        if candidate.split("/", 1)[0].split(".")[-1].lower() in _KNOWN_TLDS:
            links.append(candidate)
    return links


# Enough to tell "steam.gift" (a link) from "e.g" or "file.txt" (not a link) in bare text.
_KNOWN_TLDS = {"com", "net", "org", "io", "gg", "me", "co", "app", "dev", "info", "biz", "us", "uk", "ru", "su",
               "cn", "vn", "bd", "in", "de", "fr", "tv", "ly", "to", "cc"} | rules.SUSPICIOUS_TLDS


def hostname_of(link: str) -> str:
    if not re.match(r"^[a-z]+://", link, re.IGNORECASE):
        link = "http://" + link
    return (urlparse(link).hostname or "").lower().rstrip(".")


def registrable_domain(hostname: str) -> str:
    parts = hostname.split(".")
    if len(parts) <= 2 or re.fullmatch(r"[\d.]+", hostname):
        return hostname
    take = 3 if ".".join(parts[-2:]) in rules.MULTI_PART_SUFFIXES else 2
    return ".".join(parts[-take:])


def normalize_lookalikes(s: str) -> str:
    s = s.lower()
    for src, dst in rules.LOOKALIKE_MAP:
        s = s.replace(src, dst)
    return s


def edit_distance(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def brand_impersonation(hostname: str) -> tuple[str, str] | None:
    """Returns (brand display name, "lookalike" | "contains") or None. Same rules as lib/core.js."""
    reg = registrable_domain(hostname)
    if any(reg in domains for _, domains in rules.BRANDS.values()):
        return None
    label = reg.split(".")[0]
    norm = normalize_lookalikes(label)
    for name, domains in rules.BRANDS.values():
        for official in domains:
            off = official.split(".")[0]
            if len(off) < 5 or label == off:
                continue
            allowed = 2 if len(off) >= 8 else 1 if len(off) >= 6 else 0
            if min(edit_distance(norm, off), edit_distance(label, off)) <= allowed:
                return name, "lookalike"
    parts = [normalize_lookalikes(p) for p in re.split(r"[.-]", hostname)]
    for key, (name, _) in rules.BRANDS.items():
        if any(p == key or p.startswith(key) for p in parts):
            return name, "contains"
    return None


def score_text(text: str, trusted_domains: set[str] = frozenset()) -> tuple[list[Reason], list[str]]:
    """Content-only signals. Sender-context signals are added by the engine."""
    reasons: list[Reason] = []
    masked = MASKED_RE.findall(text)
    text = MASKED_RE.sub(lambda m: m.group(2), text)   # the label is not a link; the target is
    links = extract_links(text)
    hosts = [hostname_of(l) for l in links]
    external = [h for h in hosts if h and registrable_domain(h) not in trusted_domains]

    if external:
        reasons.append(Reason(20, "external_link", f"contains external link(s): {', '.join(sorted(set(external)))}"))

    lures = sorted({m.lower() for m in MONEY_RE.findall(text)})
    if lures or rules.MONEY_AMOUNT.search(text):
        reasons.append(Reason(25, "money_lure", "mentions money / gifts / rewards"
                              + (f" ({', '.join(lures)})" if lures else "")))

    if URGENCY_RE.search(text):
        reasons.append(Reason(10, "urgency", "creates time pressure"))

    words = re.findall(r"\w+", URL_RE.sub(" ", text))
    if external and not GREETING_RE.search(text) and len(words) <= 25:
        reasons.append(Reason(10, "no_greeting", "short, impersonal message with no greeting - unusual between colleagues"))

    for h in external:
        hit = brand_impersonation(h)
        if hit:
            name, kind = hit
            pts = 40 if kind == "lookalike" else 30
            if kind == "lookalike":
                text = f"link domain {registrable_domain(h)} is a look-alike of {name}"
            else:
                text = f"link domain {h} uses the name {name} but is not owned by {name}"
            reasons.append(Reason(pts, "brand_impersonation", text))
            break

    if any(registrable_domain(h) in rules.SHORTENERS for h in external):
        reasons.append(Reason(10, "shortener", "uses a link shortener that hides the destination"))
    if any(h.rsplit(".", 1)[-1] in rules.SUSPICIOUS_TLDS for h in external):
        reasons.append(Reason(10, "suspicious_tld", "link uses a domain extension common in phishing"))
    for label, target in masked:
        shown = {registrable_domain(hostname_of(l)) for l in extract_links(label)} - {""}
        actual = registrable_domain(hostname_of(target))
        if shown and actual not in shown:
            reasons.append(Reason(30, "masked_link", f"link text shows {', '.join(sorted(shown))} "
                                  f"but actually opens {actual}"))
            break

    if re.search(r"@(everyone|here|channel)\b", text, re.IGNORECASE):
        reasons.append(Reason(10, "mass_mention", "pings everyone"))

    return reasons, links
