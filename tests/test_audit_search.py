"""Combined time/category event search."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from linecontrol.audit.logger import Logger
from linecontrol.audit.query import EventSearch, parse_time
from linecontrol.bus import EventBus
from linecontrol.domain.events import Event
from linecontrol.domain.kinds import EventKind
from linecontrol.store.filestore import FileStore


def build(tmp_path) -> Logger:
    return Logger(FileStore(tmp_path), EventBus())


def _at(day: int, hour: int = 12) -> datetime:
    return datetime(2026, 9, day, hour, tzinfo=timezone.utc)


def seed(tmp_path) -> Logger:
    logger = build(tmp_path)
    logger.record(Event(kind=EventKind.ALARM, source="weld", message="a1", at=_at(1, 8)))
    logger.record(Event(kind=EventKind.STOP, source="line", message="s1", at=_at(1, 10)))
    logger.record(Event(kind=EventKind.ALARM, source="weld", message="a2", at=_at(2, 9)))
    logger.record(Event(kind=EventKind.PUMP, source="pump", message="p1", at=_at(3, 14)))
    logger.record(Event(kind=EventKind.ALARM, source="weld", message="a3", at=_at(4, 7)))
    return logger


def test_search_by_time_window_is_chronological(tmp_path) -> None:
    logger = seed(tmp_path)
    search = EventSearch(start=_at(1, 9), end=_at(3, 0))
    found = logger.search(search)
    assert [event.message for event in found] == ["s1", "a2"]


def test_search_time_bounds_are_inclusive(tmp_path) -> None:
    logger = seed(tmp_path)
    found = logger.search(EventSearch(start=_at(1, 10), end=_at(1, 10)))
    assert [event.message for event in found] == ["s1"]


def test_search_combines_kinds_and_window(tmp_path) -> None:
    logger = seed(tmp_path)
    search = EventSearch(
        kinds=frozenset({EventKind.ALARM, EventKind.STOP}),
        start=_at(2, 0),
    )
    found = logger.search(search)
    assert [event.message for event in found] == ["a2", "a3"]


def test_search_without_filters_matches_all(tmp_path) -> None:
    logger = seed(tmp_path)
    assert len(logger.search(EventSearch(limit=-1))) == 5


def test_search_positive_limit_keeps_newest(tmp_path) -> None:
    logger = seed(tmp_path)
    found = logger.search(EventSearch(kinds=frozenset({EventKind.ALARM}), limit=2))
    assert [event.message for event in found] == ["a2", "a3"]


def test_search_rejects_inverted_window(tmp_path) -> None:
    logger = build(tmp_path)
    with pytest.raises(ValueError):
        logger.search(EventSearch(start=_at(3), end=_at(1)))


def test_parse_time_handles_z_suffix_and_naive_input() -> None:
    assert parse_time("2026-09-01T08:00:00Z") == _at(1, 8)
    assert parse_time("2026-09-01T08:00:00") == _at(1, 8)
    with pytest.raises(ValueError):
        parse_time("not a stamp")
    with pytest.raises(ValueError):
        parse_time("   ")
