"""Event queries."""

from __future__ import annotations

from ..domain.events import Event
from ..domain.filter import EventFilter
from ..domain.kinds import EventKind
from .state import DEFAULT_QUERY_LIMIT


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

    def search(self, event_filter: EventFilter) -> list[Event]:
        """All events matching the filter, oldest first."""

        return [event for event in self.state.events if event_filter.matches(event)]

    def recent(self, limit: int) -> list[Event]:
        if limit <= 0:
            return []
        return self.state.events[-limit:]
