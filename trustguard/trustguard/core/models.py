"""Platform-neutral data types. Adapters convert Discord/Slack events into these."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class Action(str, Enum):
    ALLOW = "allow"
    WARN = "warn"
    QUARANTINE = "quarantine"


@dataclass(frozen=True)
class Message:
    platform: str                 # "discord", "slack", ...
    message_id: str
    sender_id: str
    destination_id: str           # channel / DM / thread the message went to
    text: str
    sent_at: datetime
    sender_created_at: datetime | None = None  # account creation time, when the platform exposes it
    is_direct: bool = False


@dataclass
class Reason:
    points: int
    code: str
    text: str


@dataclass
class Verdict:
    action: Action
    score: int
    reasons: list[Reason] = field(default_factory=list)
    links: list[str] = field(default_factory=list)

    def summary(self) -> str:
        return "; ".join(r.text for r in self.reasons) or "no risk signals"


@dataclass(frozen=True)
class JoinEvent:
    platform: str
    user_id: str
    username: str
    display_name: str
    joined_at: datetime
    account_created_at: datetime | None = None


@dataclass
class JoinDecision:
    hold: bool
    reasons: list[str] = field(default_factory=list)
