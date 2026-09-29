"""Immutable investigation archives exported from the audit log."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import zipfile
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any

from ..domain.events import Event, utcnow
from ..domain.filter import EventFilter
from ..store.filestore import FileStore

#: Files every valid archive zip contains.
EVENTS_JSON = "events.json"
EVENTS_CSV = "events.csv"
MANIFEST_NAME = "MANIFEST.json"
SHA_SUMS = "SHA256SUMS"

#: Event fields rendered into the CSV view, in column order.
CSV_FIELDS = ("at", "kind", "source", "message", "payload")

#: Version marker for the on-disk ledger layout.
LEDGER_VERSION = 1

GENESIS = "GENESIS"


@dataclass(frozen=True, slots=True)
class ArchiveRecord:
    """One append-only ledger entry describing an exported archive."""

    archive: str
    created_at: str
    count: int
    first_at: str | None
    last_at: str | None
    event_digest: str
    zip_sha256: str
    filter: dict[str, object]
    prev_digest: str
    digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "archive": self.archive,
            "createdAt": self.created_at,
            "count": self.count,
            "firstAt": self.first_at,
            "lastAt": self.last_at,
            "eventDigest": self.event_digest,
            "zipSha256": self.zip_sha256,
            "filter": self.filter,
            "prevDigest": self.prev_digest,
            "digest": self.digest,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "ArchiveRecord":
        return cls(
            archive=str(raw["archive"]),
            created_at=str(raw["createdAt"]),
            count=int(raw["count"]),
            first_at=(str(raw["firstAt"]) if raw.get("firstAt") else None),
            last_at=(str(raw["lastAt"]) if raw.get("lastAt") else None),
            event_digest=str(raw["eventDigest"]),
            zip_sha256=str(raw["zipSha256"]),
            filter=dict(raw["filter"]),
            prev_digest=str(raw["prevDigest"]),
            digest=str(raw["digest"]),
        )


def canonical_event(event: Event) -> bytes:
    """Deterministic bytes for one event in the hash chain."""

    return json.dumps(event.to_dict(), sort_keys=True, ensure_ascii=False).encode(
        "utf-8"
    )


def event_chain(events: list[Event]) -> str:
    """SHA-256 chain over the events; each link binds the previous one."""

    digest = GENESIS
    for event in events:
        digest = hashlib.sha256(digest.encode("ascii") + canonical_event(event)).hexdigest()
    return digest


def entry_digest(record: ArchiveRecord) -> str:
    """Seal a ledger entry by hashing its content and the previous link."""

    body = {
        "archive": record.archive,
        "createdAt": record.created_at,
        "count": record.count,
        "firstAt": record.first_at,
        "lastAt": record.last_at,
        "eventDigest": record.event_digest,
        "zipSha256": record.zip_sha256,
        "filter": record.filter,
        "prevDigest": record.prev_digest,
    }
    raw = json.dumps(body, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def events_csv(events: list[Event]) -> bytes:
    """Render the events as UTF-8 CSV (BOM keeps Excel happy)."""

    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=CSV_FIELDS)
    writer.writeheader()
    for event in events:
        writer.writerow(
            {
                "at": event.at.isoformat(),
                "kind": event.kind.value,
                "source": event.source,
                "message": event.message,
                "payload": event.payload,
            }
        )
    return ("﻿" + buffer.getvalue()).encode("utf-8")


def build_zip(
    events: list[Event],
    event_filter: EventFilter,
    created_at: datetime,
) -> tuple[bytes, str]:
    """Pack the query window; returns the zip bytes and its SHA-256."""

    json_payload = json.dumps(
        [event.to_dict() for event in events],
        ensure_ascii=False,
        indent=2,
    ).encode("utf-8")
    csv_payload = events_csv(events)
    files = {
        EVENTS_JSON: json_payload,
        EVENTS_CSV: csv_payload,
    }

    hashes = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
    manifest = {
        "createdAt": created_at.isoformat(),
        "count": len(events),
        "firstAt": events[0].at.isoformat() if events else None,
        "lastAt": events[-1].at.isoformat() if events else None,
        "eventDigest": event_chain(events),
        "filter": event_filter.to_dict(),
        "files": hashes,
    }
    manifest_payload = json.dumps(manifest, ensure_ascii=False, indent=2).encode(
        "utf-8"
    )
    sums_payload = "".join(
        f"{digest}  {name}\n" for name, digest in sorted(hashes.items())
    ).encode("ascii")

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(files.items()):
            archive.writestr(name, data)
        archive.writestr(MANIFEST_NAME, manifest_payload)
        archive.writestr(SHA_SUMS, sums_payload)
    payload = buffer.getvalue()
    return payload, hashlib.sha256(payload).hexdigest()


def inspect_zip(payload: bytes) -> dict[str, Any]:
    """Validate archive members against the manifest.

    Returns the parsed manifest on success; raises :class:`ValueError` when
    any member is missing, tampered or fails the event hash chain.
    """

    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        try:
            manifest = json.loads(archive.read(MANIFEST_NAME).decode("utf-8"))
        except KeyError as error:
            raise ValueError(f"archive is missing {MANIFEST_NAME}") from error
        files = manifest.get("files", {})
        for name, expected in files.items():
            try:
                data = archive.read(name)
            except KeyError as error:
                raise ValueError(f"archive is missing member {name!r}") from error
            actual = hashlib.sha256(data).hexdigest()
            if actual != expected:
                raise ValueError(f"member {name!r} checksum mismatch")
        try:
            raw_events = json.loads(archive.read(EVENTS_JSON).decode("utf-8"))
        except KeyError as error:
            raise ValueError(f"archive is missing {EVENTS_JSON}") from error

    events = [Event.from_dict(item) for item in raw_events]
    if event_chain(events) != manifest.get("eventDigest"):
        raise ValueError("event hash chain mismatch")
    if len(events) != manifest.get("count"):
        raise ValueError("event count mismatch")
    if not manifest.get("filter"):
        raise ValueError("manifest is missing the export filter")
    replayed = EventFilter.from_dict(manifest["filter"])
    for event in events:
        if not replayed.matches(event):
            raise ValueError("event outside the exported filter window")
    return manifest


class ArchiveStore:
    """Builds read-only investigation archives and a hash-chained ledger."""

    def __init__(self, store: FileStore) -> None:
        self._store = store

    @property
    def store(self) -> FileStore:
        return self._store

    def export(self, events: list[Event], event_filter: EventFilter) -> ArchiveRecord:
        """Archive the query window; refused if the window is empty."""

        if not events:
            raise ValueError("no events match the filter; nothing to export")

        created = utcnow()
        payload, zip_digest = build_zip(events, event_filter, created)
        name = f"audit-{created:%Y%m%dT%H%M%S}-{zip_digest[:12]}.zip"

        entries = self._read_ledger()
        prev_digest = entries[-1].digest if entries else GENESIS
        record = ArchiveRecord(
            archive=name,
            created_at=created.isoformat(),
            count=len(events),
            first_at=events[0].at.isoformat(),
            last_at=events[-1].at.isoformat(),
            event_digest=event_chain(events),
            zip_sha256=zip_digest,
            filter=event_filter.to_dict(),
            prev_digest=prev_digest,
            digest="",
        )
        record = replace(record, digest=entry_digest(record))
        entries.append(record)
        self._store.archive_save(name, payload)
        self._write_ledger(entries)
        return record

    def fetch(self, name: str) -> tuple[bytes, ArchiveRecord] | None:
        """Return the archive bytes together with its ledger record."""

        payload = self._store.archive_load(name)
        if payload is None:
            return None
        record = next(
            (entry for entry in self._read_ledger() if entry.archive == name), None
        )
        if record is None:
            raise KeyError(name)
        return payload, record

    def list(self) -> list[ArchiveRecord]:
        return self._read_ledger()

    def verify(self, name: str) -> dict[str, Any]:
        """Check the file on disk against the archive contents and ledger."""

        located = self.fetch(name)
        if located is None:
            raise FileNotFoundError(name)
        payload, record = located
        result: dict[str, Any] = {"archive": name, "ok": False, "errors": []}
        actual = hashlib.sha256(payload).hexdigest()
        if actual != record.zip_sha256:
            result["errors"].append("zip checksum mismatch with ledger")
        try:
            manifest = inspect_zip(payload)
        except ValueError as error:
            result["errors"].append(str(error))
            return result
        if manifest.get("eventDigest") != record.event_digest:
            result["errors"].append("event digest mismatch with ledger")
        if self._store.is_readonly_archive(name):
            result["readonly"] = True
        else:
            result["readonly"] = False
            result["errors"].append("archive file is writable")
        result["ok"] = not result["errors"]
        return result

    def verify_ledger(self) -> dict[str, Any]:
        """Walk the ledger hash chain and cross-check the files on disk."""

        entries = self._read_ledger()
        errors: list[str] = []
        prev = GENESIS
        for index, record in enumerate(entries):
            if record.prev_digest != prev:
                errors.append(f"entry {index} ({record.archive}): broken chain link")
            if record.digest != entry_digest(record):
                errors.append(f"entry {index} ({record.archive}): digest mismatch")
            prev = record.digest
            if self._store.archive_load(record.archive) is None:
                errors.append(f"entry {index} ({record.archive}): file missing")
        return {"ok": not errors, "errors": errors, "count": len(entries)}

    def is_readonly(self, name: str) -> bool:
        return self._store.is_readonly_archive(name)

    # -- ledger plumbing ------------------------------------------------

    def _read_ledger(self) -> list[ArchiveRecord]:
        raw = self._store.ledger_load()
        if raw is None or not raw.strip():
            return []
        try:
            decoded = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("export ledger is corrupt") from error
        if not isinstance(decoded, dict) or decoded.get("version") != LEDGER_VERSION:
            raise ValueError("export ledger version is unsupported")
        items = decoded.get("entries")
        if not isinstance(items, list):
            raise ValueError("export ledger is corrupt")
        return [ArchiveRecord.from_dict(item) for item in items]

    def _write_ledger(self, entries: list[ArchiveRecord]) -> None:
        payload = json.dumps(
            {"version": LEDGER_VERSION, "entries": [e.to_dict() for e in entries]},
            ensure_ascii=False,
            indent=2,
        ).encode("utf-8")
        self._store.ledger_replace(payload)
