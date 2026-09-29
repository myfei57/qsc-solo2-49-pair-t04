"""Signed archive export and verification."""

from __future__ import annotations

import io
import json
import zipfile
from datetime import datetime, timezone

import pytest

from linecontrol.audit import archive
from linecontrol.audit.logger import Logger
from linecontrol.audit.query import EventSearch
from linecontrol.bus import EventBus
from linecontrol.domain.events import Event
from linecontrol.domain.kinds import EventKind
from linecontrol.store.filestore import FileStore


def build(tmp_path) -> Logger:
    return Logger(FileStore(tmp_path), EventBus())


def seed(tmp_path) -> Logger:
    logger = build(tmp_path)
    logger.record(Event(kind=EventKind.ALARM, source="weld", message="trip",
                        at=datetime(2026, 9, 1, 8, tzinfo=timezone.utc)))
    logger.record(Event(kind=EventKind.STOP, source="line", message="halt",
                        at=datetime(2026, 9, 1, 10, tzinfo=timezone.utc)))
    return logger


def _zip_entries(blob: bytes) -> dict[str, bytes]:
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        return {name: zf.read(name) for name in zf.namelist()}


def test_secret_is_created_once_with_owner_mode(tmp_path) -> None:
    store = FileStore(tmp_path)
    first = archive.load_or_create_secret(store)
    second = archive.load_or_create_secret(store)
    assert first == second and len(first) == 32
    assert (tmp_path / archive.KEY_SECRET).exists()


def test_export_roundtrip_and_manifest_contents(tmp_path) -> None:
    logger = seed(tmp_path)
    search = EventSearch(kinds=frozenset({EventKind.ALARM, EventKind.STOP}))
    blob, receipt = logger.export_search(search)
    assert receipt["eventCount"] == 2
    assert receipt["sha256"] == archive.sha256_hex(blob)

    entries = _zip_entries(blob)
    assert set(entries) == {
        archive.EVENTS_NAME, archive.MANIFEST_NAME,
        archive.SUMS_NAME, archive.SIGNATURE_NAME,
    }
    result = logger.verify_archive_blob(blob)
    assert result["manifest"]["eventCount"] == 2
    criteria = result["manifest"]["criteria"]
    assert criteria["kinds"] == ["alarm", "stop"]
    assert [event["message"] for event in result["events"]] == ["trip", "halt"]


def test_export_ignores_search_limit_and_records_ledger(tmp_path) -> None:
    logger = seed(tmp_path)
    blob, receipt = logger.export_search(EventSearch(limit=1))
    assert receipt["eventCount"] == 2
    ledger = logger.export_ledger()
    assert len(ledger) == 1 and ledger[0]["archiveId"] == receipt["archiveId"]


def test_export_records_itself_as_audit_event_without_self_inclusion(tmp_path) -> None:
    logger = seed(tmp_path)
    _, receipt = logger.export_search(EventSearch(limit=-1))
    assert receipt["eventCount"] == 2
    assert logger.events()[-1].source == "audit.export"


def _rebuild_member(blob: bytes, name: str, new_body: bytes, keep_sums: bool = False) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(blob)) as src, zipfile.ZipFile(buffer, "w") as dst:
        for member in src.infolist():
            body = new_body if member.filename == name else src.read(member.filename)
            dst.writestr(member, body)
    return buffer.getvalue()


def test_tampering_an_event_breaks_verification(tmp_path) -> None:
    logger = seed(tmp_path)
    blob, _ = logger.export_search(EventSearch())
    entries = _zip_entries(blob)
    changed = json.loads(entries[archive.EVENTS_NAME])
    changed[0]["message"] = "forged"
    forged = _rebuild_member(blob, archive.EVENTS_NAME,
                             json.dumps(changed).encode("utf-8"))
    with pytest.raises(archive.ArchiveError, match="hash"):
        logger.verify_archive_blob(forged)


def test_tampering_the_manifest_breaks_verification(tmp_path) -> None:
    logger = seed(tmp_path)
    blob, _ = logger.export_search(EventSearch())
    entries = _zip_entries(blob)
    manifest = json.loads(entries[archive.MANIFEST_NAME])
    manifest["eventCount"] = 99
    forged = _rebuild_member(blob, archive.MANIFEST_NAME,
                             json.dumps(manifest).encode("utf-8"))
    with pytest.raises(archive.ArchiveError):
        logger.verify_archive_blob(forged)


def test_forged_signature_is_rejected(tmp_path) -> None:
    logger = seed(tmp_path)
    blob, _ = logger.export_search(EventSearch())
    forged = _rebuild_member(blob, archive.SIGNATURE_NAME, b"deadbeef  HMAC-SHA256\n")
    with pytest.raises(archive.ArchiveError, match="signature mismatch"):
        logger.verify_archive_blob(forged)


def test_foreign_key_is_rejected(tmp_path) -> None:
    producer = seed(tmp_path)
    blob, _ = producer.export_search(EventSearch())
    stranger = build(tmp_path / "other")
    with pytest.raises(archive.ArchiveError, match="signature mismatch"):
        stranger.verify_archive_blob(blob)


def test_non_zip_input_is_rejected(tmp_path) -> None:
    logger = build(tmp_path)
    with pytest.raises(archive.ArchiveError, match="not a valid ZIP"):
        logger.verify_archive_blob(b"this is not a zip")
