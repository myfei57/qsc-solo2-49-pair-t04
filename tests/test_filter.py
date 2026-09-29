"""Combined time-window and category filters."""

from __future__ import annotations

import pytest

from linecontrol.domain.events import Event, parse_time
from linecontrol.domain.filter import EventFilter, build_filter
from linecontrol.domain.kinds import EventKind


def event(kind: EventKind, at: str) -> Event:
    return Event(kind=kind, source="test", at=parse_time(at))


def test_open_filter_matches_everything() -> None:
    match = EventFilter()
    assert match.matches(event(EventKind.ALARM, "2026-09-28T08:00:00Z"))


def test_time_window_is_inclusive_and_bounded() -> None:
    match = build_filter("2026-09-28T08:00:00Z", "2026-09-28T16:00:00Z")
    assert match.matches(event(EventKind.ALARM, "2026-09-28T08:00:00Z"))
    assert match.matches(event(EventKind.STOP, "2026-09-28T16:00:00Z"))
    assert not match.matches(event(EventKind.ALARM, "2026-09-28T07:59:59Z"))
    assert not match.matches(event(EventKind.ALARM, "2026-09-28T16:00:01Z"))


def test_kind_set_filters_categories() -> None:
    match = build_filter(
        "",
        "",
        ["alarm,stop", "weld"],
    )
    assert match.kinds == frozenset(
        {EventKind.ALARM, EventKind.STOP, EventKind.WELD}
    )
    assert match.matches(event(EventKind.ALARM, "2026-09-28T08:00:00Z"))
    assert not match.matches(event(EventKind.PUMP, "2026-09-28T08:00:00Z"))


def test_combined_window_and_kinds() -> None:
    match = build_filter("2026-09-28T08:00:00Z", "2026-09-28T16:00:00Z", ["alarm"])
    assert not match.matches(event(EventKind.ALARM, "2026-09-28T17:00:00Z"))
    assert not match.matches(event(EventKind.STOP, "2026-09-28T10:00:00Z"))
    assert match.matches(event(EventKind.ALARM, "2026-09-28T10:00:00Z"))


def test_naive_timestamp_is_utc() -> None:
    assert parse_time("2026-09-28T08:00:00").utcoffset().total_seconds() == 0


def test_bad_timestamp_and_kind_raise() -> None:
    with pytest.raises(ValueError):
        build_filter("not-a-time")
    with pytest.raises(ValueError):
        build_filter("", "", ["bogus"])
    with pytest.raises(ValueError):
        build_filter("2026-09-28T16:00:00Z", "2026-09-28T08:00:00Z")


def test_filter_round_trips_through_dict() -> None:
    match = build_filter("2026-09-28T08:00:00Z", "2026-09-28T16:00:00Z", ["alarm,stop"])
    again = EventFilter.from_dict(match.to_dict())
    assert again == match
