"""Tamper-evident archive packages for handing audit ranges over.

An archive is a ZIP containing:

``events.json``
    The matched events, serialized exactly as they are stored.
``manifest.json``
    The query criteria, event count, creation time and per-file SHA-256
    hashes (including ``events.json``).
``SHA256SUMS``
    The per-file hashes in the classical ``<hash>  <name>`` layout.
``signature.txt``
    HMAC-SHA256 of the ``SHA256SUMS`` text under the site key.

Changing an event breaks the ``events.json`` hash; changing the manifest
breaks either the hash listing or the signature, so verification detects
every layer of tampering.  The symmetric site key is generated on first
use and held outside the store data directory; the operator must hand it
to the receiving party out of band.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import secrets
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..domain.events import Event, utcnow
from ..domain.kinds import EventKind
from ..store.keys import KEY_ARCHIVE_LEDGER, KEY_ARCHIVE_SECRET
from .query import EventSearch

#: Store key holding the generated site HMAC key.
KEY_SECRET = KEY_ARCHIVE_SECRET

#: Store key holding the append-only list of export receipts.
KEY_LEDGER = KEY_ARCHIVE_LEDGER

#: Number of export receipts retained on disk.
MAX_LEDGER = 200

EVENTS_NAME = "events.json"
MANIFEST_NAME = "manifest.json"
SUMS_NAME = "SHA256SUMS"
SIGNATURE_NAME = "signature.txt"

ARCHIVE_VERSION = 1
SIGNATURE_ALGORITHM = "HMAC-SHA256"


class ArchiveError(ValueError):
    """Raised when an archive cannot be built or fails verification."""


def _iso(stamp: datetime | None) -> str | None:
    return stamp.isoformat() if stamp is not None else None


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_or_create_secret(store: Any) -> bytes:
    """Return the site HMAC key, generating it once with owner-only mode."""

    raw = store.load(KEY_SECRET)
    if raw and raw.strip():
        return bytes.fromhex(raw.strip().decode("ascii"))
    key = secrets.token_bytes(32)
    store.save(KEY_SECRET, key.hex().encode("ascii"))
    path = Path(store.directory) / KEY_SECRET
    try:
        os.chmod(path, 0o600)
    except OSError:
        # Restrictive modes are best effort on non-POSIX storage.
        pass
    return key


@dataclass(frozen=True, slots=True)
class ArchiveCriteria:
    """Query scope recorded inside the archive manifest."""

    kinds: tuple[str, ...] | None
    start: datetime | None
    end: datetime | None

    @classmethod
    def from_search(cls, search: EventSearch) -> "ArchiveCriteria":
        kinds = None if search.kinds is None else tuple(sorted(k.value for k in search.kinds))
        return cls(kinds=kinds, start=search.start, end=search.end)

    def to_dict(self) -> dict[str, Any]:
        return {"kinds": list(self.kinds) if self.kinds is not None else None,
                "start": _iso(self.start), "end": _iso(self.end)}


def _payload_hash(events: list[Event]) -> str:
    """Stable hash of the event payload, independent of archive metadata."""

    digest = hashlib.sha256()
    for event in events:
        digest.update(json.dumps(event.to_dict(), ensure_ascii=False,
                                 sort_keys=True).encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def _build_manifest(
    events: list[Event],
    criteria: ArchiveCriteria,
    created_at: datetime,
    events_sha: str,
) -> bytes:
    manifest = {
        "version": ARCHIVE_VERSION,
        "createdAt": created_at.isoformat(),
        "criteria": criteria.to_dict(),
        "eventCount": len(events),
        "eventsSha256": events_sha,
        "payloadSha256": _payload_hash(events),
        "signatureAlgorithm": SIGNATURE_ALGORITHM,
    }
    return json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")


def _sums_text(file_hashes: dict[str, str]) -> bytes:
    lines = [f"{digest}  {name}" for name, digest in sorted(file_hashes.items())]
    return ("\n".join(lines) + "\n").encode("utf-8")


def build_archive(
    events: list[Event],
    criteria: ArchiveCriteria,
    secret: bytes,
    created_at: datetime | None = None,
) -> bytes:
    """Serialize matched events into a signed archive, returned as ZIP bytes.

    The integrity chain is one-directional: the events hash is recorded in
    the manifest, both file hashes are listed in SHA256SUMS, and that list
    is HMAC-signed, so no layer can be altered without breaking the next.
    """

    stamp = created_at or utcnow()
    events_body = json.dumps(
        [event.to_dict() for event in events], ensure_ascii=False, indent=2
    ).encode("utf-8")
    events_sha = sha256_hex(events_body)
    manifest_body = _build_manifest(events, criteria, stamp, events_sha)
    manifest_sha = sha256_hex(manifest_body)

    sums_body = _sums_text({EVENTS_NAME: events_sha, MANIFEST_NAME: manifest_sha})
    signature = hmac.new(secret, sums_body, hashlib.sha256).hexdigest()
    signature_body = f"{signature}  {SIGNATURE_ALGORITHM}\n".encode("ascii")

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, body in (
            (EVENTS_NAME, events_body),
            (MANIFEST_NAME, manifest_body),
            (SUMS_NAME, sums_body),
            (SIGNATURE_NAME, signature_body),
        ):
            zf.writestr(name, body)
    return buffer.getvalue()


def _read_member(zf: zipfile.ZipFile, name: str) -> bytes:
    try:
        return zf.read(name)
    except KeyError as error:
        raise ArchiveError(f"archive is missing {name}") from error


def verify_archive(blob: bytes, secret: bytes) -> dict[str, Any]:
    """Validate every integrity layer of an archive and summarize it.

    Raises :class:`ArchiveError` on the first failed check; otherwise
    returns the manifest plus the verified event list.
    """

    try:
        zf = zipfile.ZipFile(io.BytesIO(blob))
    except zipfile.BadZipFile as error:
        raise ArchiveError("not a valid ZIP archive") from error

    with zf:
        bad = zf.testzip()
        if bad is not None:
            raise ArchiveError(f"corrupted ZIP member: {bad}")
        events_body = _read_member(zf, EVENTS_NAME)
        manifest_body = _read_member(zf, MANIFEST_NAME)
        sums_body = _read_member(zf, SUMS_NAME)
        signature_body = _read_member(zf, SIGNATURE_NAME)

        signature_text = signature_body.decode("ascii", errors="strict").strip().split()
        if len(signature_text) != 2:
            raise ArchiveError("malformed signature.txt")
        given_sig, algorithm = signature_text
        if algorithm != SIGNATURE_ALGORITHM:
            raise ArchiveError(f"unsupported signature algorithm: {algorithm}")
        expected_sig = hmac.new(secret, sums_body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(given_sig, expected_sig):
            raise ArchiveError("signature mismatch: archive or key is wrong")

        try:
            manifest = json.loads(manifest_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ArchiveError("manifest.json is not valid JSON") from error

        # Signature is checked first; now every hash it vouches for.
        expected_sums = _sums_text({
            EVENTS_NAME: manifest.get("eventsSha256"),
            MANIFEST_NAME: sha256_hex(manifest_body),
        })
        if expected_sums != sums_body:
            raise ArchiveError("SHA256SUMS does not match the archive contents")

        if sha256_hex(events_body) != manifest.get("eventsSha256"):
            raise ArchiveError("events.json hash disagrees with the manifest")

        try:
            raw_events = json.loads(events_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ArchiveError("events.json is not valid JSON") from error
        if not isinstance(raw_events, list):
            raise ArchiveError("events.json is not a JSON array")
        try:
            events = [Event.from_dict(item) for item in raw_events]
        except (KeyError, TypeError, ValueError) as error:
            raise ArchiveError(f"events.json contains an invalid event: {error}") from error

    if manifest.get("version") != ARCHIVE_VERSION:
        raise ArchiveError(f"unsupported archive version: {manifest.get('version')!r}")
    if manifest.get("signatureAlgorithm") != SIGNATURE_ALGORITHM:
        raise ArchiveError("manifest advertises a different signature algorithm")
    if manifest.get("eventCount") != len(events):
        raise ArchiveError("eventCount disagrees with events.json")
    if manifest.get("payloadSha256") != _payload_hash(events):
        raise ArchiveError("payload hash disagrees with the events")

    return {
        "manifest": manifest,
        "events": [event.to_dict() for event in events],
        "verifiedAt": utcnow().isoformat(),
    }


def archive_filename(manifest: dict[str, Any]) -> str:
    stamp = str(manifest.get("createdAt", "")).replace(":", "").replace("-", "")
    stamp = stamp.replace("+", "Z").replace(".", "")
    return f"audit-archive-{stamp}.zip"


# -- export ledger -----------------------------------------------------------

def append_ledger(store: Any, receipt: dict[str, Any]) -> list[dict[str, Any]]:
    """Persist an export receipt, keeping the newest entries capped."""

    raw = store.load(KEY_LEDGER)
    ledger: list[dict[str, Any]] = []
    if raw and raw.strip():
        try:
            decoded = json.loads(raw.decode("utf-8"))
            if isinstance(decoded, list):
                ledger = [item for item in decoded if isinstance(item, dict)]
        except (UnicodeDecodeError, json.JSONDecodeError):
            ledger = []
    ledger.append(receipt)
    if len(ledger) > MAX_LEDGER:
        del ledger[: len(ledger) - MAX_LEDGER]
    store.save(KEY_LEDGER, json.dumps(ledger, ensure_ascii=False).encode("utf-8"))
    return ledger


def read_ledger(store: Any) -> list[dict[str, Any]]:
    raw = store.load(KEY_LEDGER)
    if not raw or not raw.strip():
        return []
    try:
        decoded = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return []
    if not isinstance(decoded, list):
        return []
    return [item for item in decoded if isinstance(item, dict)]


def kinds_for_search(kinds: Any) -> frozenset[EventKind] | None:
    """Build the kind set from API values; ``None``/empty means all kinds."""

    if kinds is None:
        return None
    values: list[str] = []
    for item in kinds:
        values.extend(part.strip() for part in item.split(",") if part.strip())
    if not values:
        return None
    resolved = frozenset(EventKind(value) for value in values)
    return resolved or None


def utc_stamp() -> datetime:
    return datetime.now(timezone.utc)
