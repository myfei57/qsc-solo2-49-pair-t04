"""Combined event filter: time window plus event categories."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from .events import Event, parse_time
from .kinds import EventKind


@dataclass(frozen=True, slots=True)
class EventFilter:
    """Matches events inside ``[start, end]`` whose kind is selected.

    An empty ``kinds`` set means every category; open bounds are unrestricted.
    Both time bounds are inclusive so an event logged exactly on a shift
    boundary belongs to the investigation window.
    """

    start: datetime | None = None
    end: datetime | None = None
    kinds: frozenset[EventKind] = frozenset()

    def matches(self, event: Event) -> bool:
        if self.start is not None and event.at < self.start:
            return False
        if self.end is not None and event.at > self.end:
            return False
        if self.kinds and event.kind not in self.kinds:
            return False
        return True

    def to_dict(self) -> dict[str, object]:
        return {
            "start": self.start.isoformat() if self.start else None,
            "end": self.end.isoformat() if self.end else None,
            "kinds": sorted(kind.value for kind in self.kinds),
        }

    @classmethod
    def from_dict(cls, raw: dict[str, object]) -> "EventFilter":
        start_raw = raw.get("start")
        end_raw = raw.get("end")
        values = raw.get("kinds") or ()
        return cls(
            start=parse_time(str(start_raw)) if start_raw else None,
            end=parse_time(str(end_raw)) if end_raw else None,
            kinds=frozenset(EventKind(str(value)) for value in values),
        )


def build_filter(
    start_raw: str = "",
    end_raw: str = "",
    kind_values: list[str] | tuple[str, ...] | None = None,
) -> EventFilter:
    """Parse request-supplied bounds and category values into a filter.

    Raises :class:`ValueError` for malformed timestamps or unknown kinds.
    """

    start = parse_time(start_raw) if start_raw else None
    end = parse_time(end_raw) if end_raw else None
    if start is not None and end is not None and start > end:
        raise ValueError("start time is later than end time")

    kinds: set[EventKind] = set()
    for raw in kind_values or ():
        for part in raw.split(","):
            token = part.strip()
            if not token:
                continue
            try:
                kinds.add(EventKind(token))
            except ValueError as error:
                raise ValueError(f"unknown event kind: {token!r}") from error
    return EventFilter(start=start, end=end, kinds=frozenset(kinds))
