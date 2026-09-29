"""Event queries: single-kind lookup and combined time/category search."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from ..domain.events import Event
from ..domain.kinds import EventKind
from .state import DEFAULT_QUERY_LIMIT


def parse_time(raw: str) -> datetime:
    """Parse an ISO-8601 stamp; naive stamps are interpreted as UTC."""

    text = raw.strip()
    if not text:
        raise ValueError("empty timestamp")
    try:
        stamp = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"invalid ISO-8601 timestamp: {raw!r}") from error
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp.astimezone(timezone.utc)


@dataclass(frozen=True, slots=True)
class EventSearch:
    """Combined filter.

    ``kinds`` of ``None`` matches every category.  Both time bounds are
    inclusive; ``limit`` 0 means the default cap, a negative value means
    unlimited (used by archive exports so a handoff never silently drops
    matching records).
    """

    kinds: frozenset[EventKind] | None = None
    start: datetime | None = None
    end: datetime | None = None
    limit: int = 0


class QueryOps:
    """Mixed into :class:`~linecontrol.audit.logger.Logger`."""

    def query(self, kind: EventKind, limit: int = 0) -> list[Event]:
        """Newest-first events of one kind."""

        cap = limit if limit > 0 else DEFAULT_QUERY_LIMIT
        found: list[Event] = []
        for event in reversed(self.state.events):
            if event.kind is kind:
                found.append(event)
                if len(found) >= cap:
                    break
        return found

    def recent(self, limit: int) -> list[Event]:
        if limit <= 0:
            return []
        return self.state.events[-limit:]

    def search(self, search: EventSearch) -> list[Event]:
        """Chronological events matching the combined filter."""

        if search.start is not None and search.end is not None and search.start > search.end:
            raise ValueError("search start is after end")
        matched: list[Event] = []
        for event in self.state.events:
            if search.kinds is not None and event.kind not in search.kinds:
                continue
            if search.start is not None and event.at < search.start:
                continue
            if search.end is not None and event.at > search.end:
                continue
            matched.append(event)
        if search.limit < 0:
            return matched
        cap = search.limit if search.limit > 0 else DEFAULT_QUERY_LIMIT
        return matched[-cap:]
