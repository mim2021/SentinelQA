"""Re-verification protocol for joins.

In the incident, removing the hijacked account was not enough: the attacker came back with a
NEW account and nothing asked who they were. Matching on user id alone cannot catch that, so a
join is held for admin approval when any of these hold:
  - the user id was removed / banned before
  - the name closely resembles a removed or compromised account
  - the account itself is very new
  - the community is in lockdown after a compromise (every join is held for a while)

With a state path, removals, approvals and the lockdown survive a restart (SQLite). Only ids,
names and timestamps are stored, never message content: a bot restart must not reopen the
re-infiltration gap, and the store must not become a log of people's conversations.
"""

from __future__ import annotations

import re
import sqlite3
import threading
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timedelta

from .models import JoinDecision, JoinEvent
from .scoring import edit_distance, normalize_lookalikes


def normalize_name(name: str) -> str:
    ascii_name = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode()
    return re.sub(r"[^a-z0-9]", "", normalize_lookalikes(ascii_name))


@dataclass
class RemovedAccount:
    user_id: str
    names: tuple[str, ...]
    removed_at: datetime
    compromised: bool


class RejoinPolicy:
    def __init__(self, min_account_age: timedelta = timedelta(days=7),
                 lockdown: timedelta = timedelta(hours=72),
                 state_path: str | None = None):
        self.min_account_age = min_account_age
        self.lockdown_length = lockdown
        self._removed: dict[str, RemovedAccount] = {}
        self._lockdown_until: datetime | None = None
        self._approved: set[str] = set()
        # Slack Bolt runs handlers on a thread pool, so the connection is shared under a lock.
        self._db = sqlite3.connect(state_path, check_same_thread=False) if state_path else None
        self._lock = threading.Lock()
        if self._db:
            self._load()

    def _load(self) -> None:
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS removed (user_id TEXT PRIMARY KEY, names TEXT NOT NULL,
                                                removed_at TEXT NOT NULL, compromised INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS approved (user_id TEXT PRIMARY KEY);
            CREATE TABLE IF NOT EXISTS lockdown (id INTEGER PRIMARY KEY CHECK (id = 1), until TEXT NOT NULL);
        """)
        for uid, names, at, comp in self._db.execute("SELECT user_id, names, removed_at, compromised FROM removed"):
            self._removed[uid] = RemovedAccount(uid, tuple(n for n in names.split("\n") if n),
                                                datetime.fromisoformat(at), bool(comp))
        self._approved = {uid for (uid,) in self._db.execute("SELECT user_id FROM approved")}
        row = self._db.execute("SELECT until FROM lockdown").fetchone()
        self._lockdown_until = datetime.fromisoformat(row[0]) if row else None

    def record_removal(self, user_id: str, names: list[str], at: datetime, compromised: bool = False) -> None:
        self._removed[user_id] = RemovedAccount(user_id, tuple(n for n in names if n), at, compromised)
        self._approved.discard(user_id)
        if compromised:
            self._lockdown_until = at + self.lockdown_length
        if self._db:
            with self._lock, self._db:
                self._db.execute("INSERT OR REPLACE INTO removed VALUES (?, ?, ?, ?)",
                                 (user_id, "\n".join(self._removed[user_id].names), at.isoformat(), int(compromised)))
                self._db.execute("DELETE FROM approved WHERE user_id = ?", (user_id,))
                if compromised:
                    self._db.execute("INSERT OR REPLACE INTO lockdown VALUES (1, ?)", (self._lockdown_until.isoformat(),))

    def close(self) -> None:
        if self._db:
            self._db.close()
            self._db = None

    def approve(self, user_id: str) -> None:
        self._approved.add(user_id)
        if self._db:
            with self._lock, self._db:
                self._db.execute("INSERT OR IGNORE INTO approved VALUES (?)", (user_id,))

    def in_lockdown(self, at: datetime) -> bool:
        return self._lockdown_until is not None and at < self._lockdown_until

    def evaluate(self, join: JoinEvent, include_lockdown: bool = True) -> JoinDecision:
        """include_lockdown=False checks identity only, e.g. an existing member joining one more
        channel, which a post-compromise lockdown should not hold."""
        if join.user_id in self._approved:
            return JoinDecision(hold=False, reasons=["approved by an admin"])

        reasons: list[str] = []
        if join.user_id in self._removed:
            prev = self._removed[join.user_id]
            reasons.append("this account was " + ("flagged as compromised" if prev.compromised else "removed") + " earlier")

        candidates = {normalize_name(n) for n in (join.username, join.display_name) if n}
        for prev in self._removed.values():
            if prev.user_id == join.user_id:
                continue
            for old in (normalize_name(n) for n in prev.names):
                if len(old) >= 4 and any(c and edit_distance(c, old) <= max(1, len(old) // 6) for c in candidates):
                    reasons.append(f"name resembles removed account {prev.names[0]!r}")
                    break

        if join.account_created_at and join.joined_at - join.account_created_at < self.min_account_age:
            age = join.joined_at - join.account_created_at
            reasons.append(f"account is only {age.days} day(s) old")

        if include_lockdown and self.in_lockdown(join.joined_at):
            reasons.append("community is in post-compromise lockdown")

        return JoinDecision(hold=bool(reasons), reasons=reasons)
