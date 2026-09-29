"""Process event value object."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .kinds import EventKind


def utcnow() -> datetime:
    """Return an aware UTC timestamp with the process clock."""

    return datetime.now(timezone.utc)


def parse_time(raw: str) -> datetime:
    """Parse an ISO 8601 stamp; naive input is interpreted as UTC."""

    text = raw.strip()
    if not text:
        raise ValueError("empty timestamp")
    if text[-1:] in {"Z", "z"}:
        text = text[:-1] + "+00:00"
    try:
        stamp = datetime.fromisoformat(text)
    except ValueError as error:
        raise ValueError(f"invalid timestamp: {raw!r}") from error
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp.astimezone(timezone.utc)


@dataclass(frozen=True, slots=True)
class Event:
    """A single process event carried on the bus."""

    kind: EventKind
    source: str
    message: str = ""
    payload: float = 0.0
    at: datetime = field(default_factory=utcnow)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "source": self.source,
            "message": self.message,
            "payload": self.payload,
            "at": self.at.isoformat(),
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Event":
        at = raw.get("at")
        if isinstance(at, str):
            stamp = datetime.fromisoformat(at)
        elif isinstance(at, datetime):
            stamp = at
        else:
            stamp = utcnow()
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=timezone.utc)
        kind = raw.get("kind", EventKind.AUDIT.value)
        return cls(
            kind=EventKind(kind),
            source=str(raw.get("source", "")),
            message=str(raw.get("message", "")),
            payload=float(raw.get("payload", 0.0)),
            at=stamp,
        )
