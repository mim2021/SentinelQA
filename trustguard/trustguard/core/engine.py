"""TrustGuard engine: the one object adapters talk to.

Short-lived detection state (bursts, reports, per-sender domain history) is in memory. The
re-verification state (removals, approvals, lockdown) is persisted when `state_path` is set."""

from __future__ import annotations

import os
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .mass_message import MassMessageDetector, ReportTracker
from .models import Action, JoinDecision, JoinEvent, Message, Reason, Verdict
from .reverify import RejoinPolicy
from .scoring import extract_links, registrable_domain, hostname_of, score_text


@dataclass
class EngineConfig:
    warn_at: int = 35
    quarantine_at: int = 60
    new_account_age: timedelta = timedelta(days=7)
    trusted_domains: set[str] = field(default_factory=set)
    state_path: str | None = None   # SQLite file for re-verification state; None = memory only

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "EngineConfig":
        env = os.environ if env is None else env
        trusted = {d.strip().lower() for d in env.get("TRUSTGUARD_TRUSTED_DOMAINS", "").split(",") if d.strip()}
        return cls(warn_at=int(env.get("TRUSTGUARD_WARN_AT") or cls.warn_at),
                   quarantine_at=int(env.get("TRUSTGUARD_QUARANTINE_AT") or cls.quarantine_at),
                   trusted_domains=trusted,
                   state_path=env.get("TRUSTGUARD_STATE_PATH") or None)


class TrustGuard:
    def __init__(self, config: EngineConfig | None = None,
                 mass: MassMessageDetector | None = None,
                 reports: ReportTracker | None = None,
                 rejoin: RejoinPolicy | None = None):
        self.config = config or EngineConfig()
        self.mass = mass or MassMessageDetector()
        self.reports = reports or ReportTracker()
        self.rejoin = rejoin or RejoinPolicy(min_account_age=self.config.new_account_age,
                                               state_path=self.config.state_path)
        self._link_domains: dict[str, set[str]] = defaultdict(set)   # sender -> domains seen before
        self._message_count: dict[str, int] = defaultdict(int)

    def _action_for(self, score: int) -> Action:
        if score >= self.config.quarantine_at:
            return Action.QUARANTINE
        if score >= self.config.warn_at:
            return Action.WARN
        return Action.ALLOW

    def process_message(self, msg: Message) -> Verdict:
        reasons, links = score_text(msg.text, self.config.trusted_domains)
        content_score = sum(r.points for r in reasons)
        domains = {registrable_domain(hostname_of(l)) for l in links} - {""}

        # Out-of-character: a sender with history suddenly posts a domain they never used before.
        history = self._link_domains[msg.sender_id]
        if domains and self._message_count[msg.sender_id] >= 5 and not (domains & history) and content_score >= 20:
            reasons.append(Reason(10, "new_domain_for_sender", "first time this sender shares this domain"))
        history |= domains
        self._message_count[msg.sender_id] += 1

        if msg.sender_created_at and msg.sent_at - msg.sender_created_at < self.config.new_account_age and links:
            reasons.append(Reason(10, "new_account", "sender's account is less than a week old"))

        spread = self.mass.observe(msg.sender_id, msg.destination_id, msg.text, msg.sent_at)
        if self.mass.is_burst(spread) and content_score > 0:
            reasons.append(Reason(35, "mass_message", f"same message sent to {spread} destinations within "
                                  f"{int(self.mass.window.total_seconds() // 60)} minutes"))

        score = min(sum(r.points for r in reasons), 100)
        return Verdict(action=self._action_for(score), score=score, reasons=reasons, links=links)

    def process_report(self, reporter_id: str, suspect_id: str | None, text: str, at: datetime) -> tuple[Verdict, bool]:
        """A user forwarded a suspicious (usually private) message. Returns the verdict on the
        content and whether reports against that sender now warrant escalation to moderators."""
        reasons, links = score_text(text, self.config.trusted_domains)
        score = min(sum(r.points for r in reasons), 100)
        verdict = Verdict(action=self._action_for(score), score=score, reasons=reasons, links=links)
        escalate = False
        if suspect_id and score > 0:
            escalate = self.reports.is_escalation(self.reports.report(suspect_id, reporter_id, at))
        return verdict, escalate

    def process_join(self, join: JoinEvent, include_lockdown: bool = True) -> JoinDecision:
        return self.rejoin.evaluate(join, include_lockdown)

    def mark_compromised(self, user_id: str, names: list[str], at: datetime) -> None:
        self.rejoin.record_removal(user_id, names, at, compromised=True)

    def record_ban(self, user_id: str, names: list[str], at: datetime) -> None:
        self.rejoin.record_removal(user_id, names, at, compromised=False)

    def approve(self, user_id: str) -> None:
        self.rejoin.approve(user_id)

    def close(self) -> None:
        self.rejoin.close()


def defang(url: str) -> str:
    """Makes a URL safe to paste into an alert without it being clickable."""
    return url.replace("http", "hxxp", 1).replace(".", "[.]")


def defang_text(text: str) -> str:
    """Defangs every link inside a message, for quoting it in a moderator alert."""
    for link in sorted(set(extract_links(text)), key=len, reverse=True):
        text = text.replace(link, defang(link))
    return text
