"""Sliding-window detectors for the "spray" stage of an account takeover: one sender pushing
the same message to many destinations, and several people reporting the same sender."""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict, deque
from datetime import datetime, timedelta


def fingerprint(text: str) -> str:
    """Case/whitespace/number-insensitive hash, so "$50" vs "$100" variants still match."""
    norm = re.sub(r"\d+", "#", re.sub(r"\s+", " ", text.lower())).strip()
    return hashlib.sha256(norm.encode()).hexdigest()[:16]


class MassMessageDetector:
    def __init__(self, threshold: int = 3, window: timedelta = timedelta(minutes=10)):
        self.threshold = threshold
        self.window = window
        self._seen: dict[tuple[str, str], deque[tuple[datetime, str]]] = defaultdict(deque)

    def observe(self, sender_id: str, destination_id: str, text: str, at: datetime) -> int:
        """Records the message; returns how many distinct destinations got it inside the window."""
        q = self._seen[(sender_id, fingerprint(text))]
        q.append((at, destination_id))
        while q and at - q[0][0] > self.window:
            q.popleft()
        return len({dest for _, dest in q})

    def is_burst(self, count: int) -> bool:
        return count >= self.threshold


class ReportTracker:
    """Bots cannot read private user-to-user DMs, so recipients forward suspicious DMs to the
    bot. Independent reports against one sender are the DM-side equivalent of a burst."""

    def __init__(self, threshold: int = 2, window: timedelta = timedelta(minutes=30)):
        self.threshold = threshold
        self.window = window
        self._reports: dict[str, deque[tuple[datetime, str]]] = defaultdict(deque)

    def report(self, suspect_id: str, reporter_id: str, at: datetime) -> int:
        q = self._reports[suspect_id]
        q.append((at, reporter_id))
        while q and at - q[0][0] > self.window:
            q.popleft()
        return len({r for _, r in q})

    def is_escalation(self, distinct_reporters: int) -> bool:
        return distinct_reporters >= self.threshold
