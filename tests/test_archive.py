"""Read-only investigation archives and the export ledger."""

from __future__ import annotations

import io
import json
import os
import stat
import zipfile

import pytest

from linecontrol.audit.archive import (
    MANIFEST_NAME,
    ArchiveStore,
    event_chain,
    inspect_zip,
)
from linecontrol.audit.logger import Logger
from linecontrol.bus import EventBus
from linecontrol.domain.events import Event, parse_time
from linecontrol.domain.filter import build_filter
from linecontrol.domain.kinds import EventKind
from linecontrol.store.filestore import FileStore


def make_logger(tmp_path) -> Logger:
    return Logger(FileStore(tmp_path), EventBus())


def feed(tmp_path, count: int = 8) -> Logger:
    logger = make_logger(tmp_path)
    for index in range(count):
        logger.record(
            Event(
                kind=EventKind.ALARM if index % 2 else EventKind.STOP,
                source="line",
                message=f"e{index}",
                at=parse_time(f"2026-09-28T{8 + index:02d}:00:00Z"),
            )
        )
    return logger


def test_export_packs_events_and_readonly_archive(tmp_path) -> None:
    logger = feed(tmp_path)
    archives = ArchiveStore(FileStore(tmp_path))
    event_filter = build_filter("2026-09-28T09:30:00Z", "2026-09-28T13:30:00Z")
    events = logger.search(event_filter)
    assert [event.message for event in events] == ["e2", "e3", "e4", "e5"]

    record = archives.export(events, event_filter)
    assert record.count == 4
    assert record.first_at.endswith("10:00:00+00:00")
    assert record.prev_digest == "GENESIS"

    path = FileStore(tmp_path).archive_path(record.archive)
    mode = stat.S_IMODE(path.stat().st_mode)
    assert not mode & stat.S_IWUSR
    with pytest.raises(PermissionError):
        path.write_bytes(b"tampered")


def test_archive_zip_contains_csv_json_and_manifest(tmp_path) -> None:
    logger = feed(tmp_path)
    event_filter = build_filter("", "", ["alarm"])
    record = logger.archives.export(logger.search(event_filter), event_filter)
    payload = FileStore(tmp_path).archive_load(record.archive)
    assert payload is not None
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        assert set(archive.namelist()) == {
            "events.json",
            "events.csv",
            MANIFEST_NAME,
            "SHA256SUMS",
        }
        manifest = json.loads(archive.read(MANIFEST_NAME))
        assert manifest["count"] == 4
        assert manifest["filter"]["kinds"] == ["alarm"]
        assert archive.read("events.csv").decode("utf-8-sig").splitlines()[0] == (
            "at,kind,source,message,payload"
        )
    assert inspect_zip(payload)["count"] == 4


def test_event_chain_detects_reordered_events(tmp_path) -> None:
    logger = feed(tmp_path, 3)
    events = logger.events()
    digest_before = event_chain(list(events))
    reordered = [events[1], events[0], events[2]]
    assert event_chain(reordered) != digest_before


def test_verify_detects_tampered_member(tmp_path) -> None:
    logger = feed(tmp_path)
    event_filter = build_filter("")
    record = logger.archives.export(logger.search(event_filter), event_filter)
    store = FileStore(tmp_path)
    path = store.archive_path(record.archive)
    os.chmod(path, stat.S_IMODE(path.stat().st_mode) | stat.S_IWUSR)

    with zipfile.ZipFile(path) as archive:
        members = {name: archive.read(name) for name in archive.namelist()}
    raw = json.loads(members["events.json"])
    raw[0]["message"] = "forged"
    members["events.json"] = json.dumps(raw).encode("utf-8")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    path.write_bytes(buffer.getvalue())

    result = logger.archives.verify(record.archive)
    assert result["ok"] is False
    assert result["errors"]


def test_ledger_chains_exports_and_flags_missing_files(tmp_path) -> None:
    store = FileStore(tmp_path)
    logger = feed(tmp_path)
    logger.archives.export(
        logger.search(build_filter("", "", ["alarm"])),
        build_filter("", "", ["alarm"]),
    )
    logger.archives.export(
        logger.search(build_filter("", "", ["stop"])),
        build_filter("", "", ["stop"]),
    )
    entries = logger.archives.list()
    assert len(entries) == 2
    assert entries[1].prev_digest == entries[0].digest
    assert logger.archives.verify_ledger()["ok"] is True

    ledger_path = store._dir / store.ARCHIVE_DIR / store.LEDGER_NAME
    mode = stat.S_IMODE(ledger_path.stat().st_mode)
    assert not mode & stat.S_IWUSR

    first = store.archive_path(entries[0].archive)
    os.chmod(first, stat.S_IMODE(first.stat().st_mode) | stat.S_IWUSR)
    os.remove(first)
    report = logger.archives.verify_ledger()
    assert report["ok"] is False
    assert any("missing" in error for error in report["errors"])


def test_export_rejects_empty_window_and_duplicate_names(tmp_path) -> None:
    logger = make_logger(tmp_path)
    with pytest.raises(ValueError):
        logger.archives.export([], build_filter(""))

    event = Event(kind=EventKind.AUDIT, source="test")
    logger.record(event)
    event_filter = build_filter("")
    record = logger.archives.export(logger.search(event_filter), event_filter)
    with pytest.raises(FileExistsError):
        FileStore(tmp_path).archive_save(record.archive, b"other")


def test_archive_refuses_path_traversal(tmp_path) -> None:
    store = FileStore(tmp_path)
    with pytest.raises(ValueError):
        store.archive_save("../evil.zip", b"x")
