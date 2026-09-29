"""Archive export and verification orchestration for the audit log."""

from __future__ import annotations

from typing import Any

from ..domain.events import Event
from ..domain.kinds import EventKind
from . import archive
from .query import EventSearch


class ExportOps:
    """Mixed into :class:`~linecontrol.audit.logger.Logger`."""

    def export_search(self, search: EventSearch) -> tuple[bytes, dict[str, Any]]:
        """Build a signed archive for a search and record a receipt.

        Exports always include every match (the search limit is ignored) so
        a handoff package can never silently drop records in scope.
        """

        unlimited = EventSearch(
            kinds=search.kinds, start=search.start, end=search.end, limit=-1
        )
        events = self.search(unlimited)
        criteria = archive.ArchiveCriteria.from_search(unlimited)
        secret = archive.load_or_create_secret(self.store)
        blob = archive.build_archive(events, criteria, secret)
        receipt = self._export_receipt(blob, events, criteria)
        archive.append_ledger(self.store, receipt)
        # Record the handoff in the log itself; excluded from this package
        # because it happens after the snapshot was taken.
        self.record(
            Event(
                kind=EventKind.AUDIT,
                source="audit.export",
                message=f"exported {len(events)} events as {receipt['archiveId'][:12]}",
            )
        )
        return blob, receipt

    def verify_archive_blob(self, blob: bytes) -> dict[str, Any]:
        secret = archive.load_or_create_secret(self.store)
        return archive.verify_archive(blob, secret)

    def export_ledger(self) -> list[dict[str, Any]]:
        return archive.read_ledger(self.store)

    def _export_receipt(
        self,
        blob: bytes,
        events: list[Event],
        criteria: archive.ArchiveCriteria,
    ) -> dict[str, Any]:
        digest = archive.sha256_hex(blob)
        return {
            "archiveId": digest,
            "exportedAt": archive.utc_stamp().isoformat(),
            "criteria": criteria.to_dict(),
            "eventCount": len(events),
            "bytes": len(blob),
            "sha256": digest,
        }
