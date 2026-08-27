"""Opt-in migration of legacy cascade-level-1 IDs in internal inventory.

Only the database binding changes; the physical tag is never written.
The existing PATCH API has no compare-and-swap: use one migrating reader and
do not edit tag bindings concurrently. A fresh read narrows, but cannot remove,
that race without a backend change.
"""

import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path

import httpx

logger = logging.getLogger(__name__)


class UIDMigrationConflict(Exception):
    """Unsafe binding: discard this scan instead of guessing or retrying it."""


def legacy_uid(uid: str) -> str | None:
    """Old driver returned CT (88) and the first three UID bytes."""
    if re.fullmatch(r"(?:[0-9A-Fa-f]{14}|[0-9A-Fa-f]{20})", uid):
        return "88" + uid[:6].upper()
    return None


def _uid(spool: dict) -> str:
    return (spool.get("tag_uid") or "").strip().upper()


class UIDMigrator:
    def __init__(self, client: httpx.AsyncClient, base: str, journal: Path):
        self.client = client
        self.base = base
        self.journal = journal

    async def _get(self, path: str, **kwargs):
        response = await self.client.get(self.base + path, **kwargs)
        response.raise_for_status()
        return response.json()

    def _record(self, status: str, spool: dict, new_uid: str):
        entry = {
            "time": datetime.now(timezone.utc).isoformat(),
            "status": status,
            "spool_id": spool["id"],
            "old_uid": spool["tag_uid"],
            "new_uid": new_uid,
        }
        # Fail before PATCH if the rollback journal cannot be persisted.
        fd = os.open(self.journal, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as stream:
            stream.write(json.dumps(entry) + "\n")
            stream.flush()
            os.fsync(stream.fileno())

    async def prepare(self, scan: dict):
        full = scan["tag_uid"].upper()
        old = legacy_uid(full)
        if old is None or scan.get("tray_uuid") or scan.get("tag_type") != "ntag":
            return

        mode = await self._get("/spoolman/status")
        if mode.get("enabled") is not False:
            raise UIDMigrationConflict("UID migration only supports internal Bambuddy inventory")

        # Include archived rows so they cannot silently cause an ambiguous match.
        spools = await self._get("/inventory/spools", params={"include_archived": "true"})
        if not isinstance(spools, list) or not all(isinstance(s, dict) for s in spools):
            raise ValueError("Invalid inventory response")
        exact = [s for s in spools if _uid(s) == full]
        if exact:
            if len(exact) != 1 or exact[0].get("archived_at"):
                raise UIDMigrationConflict(f"Full UID {full} is duplicated or archived")
            return

        candidates = [s for s in spools if _uid(s) == old]
        if not candidates:
            return  # A new tag: leave the normal pairing flow unchanged.
        if len(candidates) != 1:
            raise UIDMigrationConflict(f"Legacy UID {old} belongs to multiple spools")
        spool = candidates[0]
        if spool.get("archived_at") or spool.get("tray_uuid") or spool.get("tag_type") not in (None, "generic"):
            raise UIDMigrationConflict(f"Legacy UID {old} is archived or is not a generic binding")
        if any(legacy_uid(_uid(s)) == old for s in spools):
            raise UIDMigrationConflict(f"Legacy UID {old} shares its prefix with another full UID")

        # A human may have changed the candidate since the inventory snapshot.
        path = f"/inventory/spools/{int(spool['id'])}"
        fresh = await self._get(path)
        for key in ("id", "tag_uid", "tray_uuid", "tag_type", "archived_at", "updated_at"):
            if fresh.get(key) != spool.get(key):
                raise UIDMigrationConflict(f"Spool {spool['id']} changed during UID migration; scan again")

        self._record("pending", spool, full)
        response = await self.client.patch(self.base + path, json={"tag_uid": full})
        response.raise_for_status()
        verified = await self._get(path)
        if verified.get("id") != spool["id"] or _uid(verified) != full or verified.get("archived_at"):
            raise UIDMigrationConflict(f"Could not verify UID migration for spool {spool['id']}")
        self._record("confirmed", spool, full)
        logger.info("UID migrated: spool=%s old=%s full=%s", spool["id"], old, full)
