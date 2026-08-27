"""Tests for daemon.api_client — APIClient HTTP communication."""

import asyncio
import copy
import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from daemon.api_client import MAX_BUFFER_SIZE, APIClient
from daemon.uid_migration import UIDMigrator, legacy_uid


@pytest.fixture
def api():
    return APIClient("http://localhost:5000", "test-key")


class TestAPIClientInit:
    def test_base_url_construction(self, api):
        assert api._base == "http://localhost:5000/api/v1/spoolbuddy"

    def test_base_url_strips_trailing_slash(self):
        client = APIClient("http://localhost:5000/", "key")
        assert client._base == "http://localhost:5000/api/v1/spoolbuddy"

    def test_api_key_in_headers(self):
        client = APIClient("http://localhost:5000", "my-key")
        assert client._headers == {"X-API-Key": "my-key"}

    def test_no_api_key_empty_headers(self):
        client = APIClient("http://localhost:5000", "")
        assert client._headers == {}


class TestPost:
    @pytest.mark.asyncio
    async def test_post_success(self, api):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"ok": True}
        mock_resp.raise_for_status = MagicMock()

        api._client.post = AsyncMock(return_value=mock_resp)

        result = await api._post("/test", {"key": "value"})

        assert result == {"ok": True}
        assert api._connected is True
        assert api._backoff == 1.0
        api._client.post.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_post_failure_buffers_request(self, api):
        api._client.post = AsyncMock(side_effect=httpx.ConnectError("refused"))

        result = await api._post("/test", {"data": 1})

        assert result is None
        assert len(api._buffer) == 1
        assert api._buffer[0] == {"path": "/test", "data": {"data": 1}}

    @pytest.mark.asyncio
    async def test_post_failure_logs_connection_lost_once(self, api):
        api._connected = True
        api._client.post = AsyncMock(side_effect=httpx.ConnectError("refused"))

        await api._post("/a", {})
        assert api._connected is False

        # Second failure should not log "connection lost" again
        await api._post("/b", {})
        assert len(api._buffer) == 2

    @pytest.mark.asyncio
    async def test_post_success_resets_backoff(self, api):
        api._backoff = 16.0
        mock_resp = MagicMock()
        mock_resp.json.return_value = {}
        mock_resp.raise_for_status = MagicMock()
        api._client.post = AsyncMock(return_value=mock_resp)

        await api._post("/test", {})

        assert api._backoff == 1.0

    @pytest.mark.asyncio
    async def test_buffer_max_size(self, api):
        api._client.post = AsyncMock(side_effect=httpx.ConnectError("refused"))

        for i in range(MAX_BUFFER_SIZE + 20):
            await api._post("/test", {"i": i})

        assert len(api._buffer) == MAX_BUFFER_SIZE
        # Oldest entries should have been dropped (deque maxlen behavior)
        assert api._buffer[0]["data"]["i"] == 20


class TestHeartbeat:
    @pytest.mark.asyncio
    async def test_heartbeat_posts_to_correct_path(self, api):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"pending_command": None}
        mock_resp.raise_for_status = MagicMock()
        api._client.post = AsyncMock(return_value=mock_resp)

        result = await api.heartbeat(
            device_id="dev-1",
            nfc_ok=True,
            scale_ok=False,
            uptime_s=120,
            ip_address="192.168.1.50",
            firmware_version="0.2.2b1",
        )

        assert result == {"pending_command": None}
        call_args = api._client.post.call_args
        assert "/devices/dev-1/heartbeat" in call_args[0][0]

    @pytest.mark.asyncio
    async def test_heartbeat_flushes_buffer_on_success(self, api):
        # Pre-populate buffer
        api._buffer.append({"path": "/old", "data": {"x": 1}})

        mock_resp = MagicMock()
        mock_resp.json.return_value = {"ok": True}
        mock_resp.raise_for_status = MagicMock()
        api._client.post = AsyncMock(return_value=mock_resp)

        await api.heartbeat(device_id="d", nfc_ok=True, scale_ok=True, uptime_s=0)

        # Buffer should be flushed (post called for heartbeat + 1 buffered item)
        assert len(api._buffer) == 0

    @pytest.mark.asyncio
    async def test_heartbeat_returns_none_on_failure(self, api):
        api._client.post = AsyncMock(side_effect=httpx.ConnectError("fail"))

        result = await api.heartbeat(device_id="d", nfc_ok=True, scale_ok=True, uptime_s=0)

        assert result is None


class TestRegisterDevice:
    @pytest.mark.asyncio
    async def test_register_retries_until_success(self, api):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"device_id": "dev-1"}
        mock_resp.raise_for_status = MagicMock()

        # Fail twice, then succeed
        call_count = 0

        async def mock_post(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                raise httpx.ConnectError("refused")
            return mock_resp

        api._client.post = mock_post
        # Speed up retries
        api._backoff = 0.01
        api._max_backoff = 0.02

        result = await api.register_device(
            device_id="dev-1",
            hostname="test",
            ip_address="1.2.3.4",
        )

        assert result == {"device_id": "dev-1"}
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_register_sends_all_fields(self, api):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"ok": True}
        mock_resp.raise_for_status = MagicMock()
        api._client.post = AsyncMock(return_value=mock_resp)

        await api.register_device(
            device_id="dev-1",
            hostname="myhost",
            ip_address="10.0.0.1",
            firmware_version="0.2.2b1",
            has_nfc=True,
            has_scale=False,
            tare_offset=100,
            calibration_factor=1.05,
            nfc_reader_type="PN532",
            nfc_connection="SPI",
            has_backlight=True,
        )

        call_args = api._client.post.call_args
        payload = call_args[1]["json"]
        assert payload["device_id"] == "dev-1"
        assert payload["has_backlight"] is True
        assert payload["calibration_factor"] == 1.05


class TestReportUpdateStatus:
    @pytest.mark.asyncio
    async def test_report_update_status(self, api):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"ok": True}
        mock_resp.raise_for_status = MagicMock()
        api._client.post = AsyncMock(return_value=mock_resp)

        result = await api.report_update_status("dev-1", "updating", "Fetching...")

        assert result == {"ok": True}
        call_args = api._client.post.call_args
        assert "/devices/dev-1/update-status" in call_args[0][0]
        payload = call_args[1]["json"]
        assert payload["status"] == "updating"
        assert payload["message"] == "Fetching..."

    @pytest.mark.asyncio
    async def test_report_update_status_failure_returns_none(self, api):
        api._client.post = AsyncMock(side_effect=httpx.ConnectError("fail"))

        result = await api.report_update_status("dev-1", "error", "oops")

        assert result is None


@pytest.fixture
def migration_api(api, tmp_path):
    """Exercise actual HTTP ordering and partial failures without a real database."""
    state = {
        "rows": [
            {
                "id": 12,
                "tag_uid": "885386E3",
                "tag_type": "generic",
                "tray_uuid": None,
                "archived_at": None,
                "updated_at": "before",
                "weight_used": 123,
                "brand": "Test",
                "k_profiles": [{"id": 3}],
            }
        ],
        "requests": [],
        "offline": False,
        "patch_status": 200,
        "timeout_after_commit": False,
        "change_before_patch": False,
        "ignore_patch": False,
        "spoolman": False,
        "post_status": 200,
    }

    def handler(request):
        state["requests"].append(request)
        if state["offline"]:
            raise httpx.ConnectError("offline", request=request)
        path = request.url.path
        if request.method == "GET" and path.endswith("/spoolman/status"):
            return httpx.Response(200, json={"enabled": state["spoolman"]})
        if request.method == "GET" and path.endswith("/inventory/spools"):
            assert request.url.params["include_archived"] == "true"
            return httpx.Response(200, json=state["rows"])
        if path.endswith("/inventory/spools/12"):
            row = state["rows"][0]
            if request.method == "GET":
                if state["change_before_patch"]:
                    row["tag_uid"] = "OTHER"
                return httpx.Response(200, json=row)
            if request.method == "PATCH":
                assert json.loads(request.content) == {"tag_uid": "5386E308B50001"}
                if state["patch_status"] != 200:
                    return httpx.Response(state["patch_status"], json={"detail": "denied"})
                if not state["ignore_patch"]:
                    row["tag_uid"] = "5386E308B50001"
                    row["updated_at"] = "after"
                if state["timeout_after_commit"]:
                    raise httpx.ReadTimeout("response lost", request=request)
                return httpx.Response(200, json=row)
        if request.method == "POST":
            return httpx.Response(state["post_status"], json={"ok": True})
        raise AssertionError(f"Unexpected request: {request.method} {path}")

    api._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    api._uid_migrator = UIDMigrator(api._client, "http://localhost:5000/api/v1", tmp_path / "audit.jsonl")
    return api, state


async def _scan(api, uid="5386E308B50001", **kwargs):
    return await api.tag_scanned("dev-1", uid, tag_type="ntag", **kwargs)


def _writes(state):
    return [r for r in state["requests"] if r.method == "PATCH"]


class TestUIDMigration:
    @pytest.mark.parametrize(
        "uid,old",
        [
            ("5386e308b50001", "885386E3"),
            ("0102030405060708090A", "88010203"),
            ("11223344", None),
            ("F30E071D00000100", None),
            ("5386E308B5000Z", None),
            ("5386E308 B50001", None),
        ],
    )
    def test_legacy_id_uses_only_cascade_marker_and_first_three_bytes(self, uid, old):
        assert legacy_uid(uid) == old

    @pytest.mark.asyncio
    async def test_migrates_only_uid_before_scan_and_is_idempotent(self, migration_api):
        api, state = migration_api
        before = copy.deepcopy(state["rows"][0])
        assert await _scan(api) == {"ok": True}
        assert len(_writes(state)) == 1
        row = state["rows"][0]
        assert row == {**before, "tag_uid": "5386E308B50001", "updated_at": "after"}
        assert [(r.method, r.url.path.rsplit("/", 1)[-1]) for r in state["requests"]][-3:] == [
            ("PATCH", "12"),
            ("GET", "12"),
            ("POST", "tag-scanned"),
        ]
        assert json.loads(state["requests"][-1].content)["tag_uid"] == row["tag_uid"]
        records = [json.loads(line) for line in api._uid_migrator.journal.read_text().splitlines()]
        assert [r["status"] for r in records] == ["pending", "confirmed"]
        assert records[0]["old_uid"] == before["tag_uid"]
        assert records[1]["new_uid"] == row["tag_uid"]
        assert await _scan(api) == {"ok": True}
        assert len(_writes(state)) == 1

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "scenario",
        [
            "duplicate",
            "archived",
            "bambu",
            "tray_uuid",
            "prefix_collision",
            "concurrent_edit",
            "spoolman",
            "duplicate_full",
            "archived_full",
        ],
    )
    async def test_unsafe_bindings_block_scan_without_mutation(self, migration_api, scenario):
        api, state = migration_api
        row = state["rows"][0]
        if scenario == "duplicate":
            state["rows"].append({**row, "id": 13})
        elif scenario == "archived":
            row["archived_at"] = "yesterday"
        elif scenario == "bambu":
            row["tag_type"] = "bambulab"
        elif scenario == "tray_uuid":
            row["tray_uuid"] = "bambu-id"
        elif scenario == "prefix_collision":
            state["rows"].append({**row, "id": 13, "tag_uid": "5386E308B50002"})
        elif scenario == "concurrent_edit":
            state["change_before_patch"] = True
        elif scenario == "spoolman":
            state["spoolman"] = True
        else:
            row["tag_uid"] = "5386E308B50001"
            if scenario == "duplicate_full":
                state["rows"].append({**row, "id": 13})
            else:
                row["archived_at"] = "yesterday"
        assert await _scan(api) is None
        assert not _writes(state)
        assert not any(r.method == "POST" for r in state["requests"])
        assert not api._buffer

    @pytest.mark.asyncio
    @pytest.mark.parametrize("scenario", ["new", "four_byte", "tray_uuid", "disabled"])
    async def test_normal_scans_are_unchanged(self, migration_api, scenario):
        api, state = migration_api
        uid, kwargs = "5386E308B50001", {}
        if scenario == "new":
            state["rows"] = []
        elif scenario == "four_byte":
            uid = "11223344"
        elif scenario == "tray_uuid":
            kwargs["tray_uuid"] = "bambu-id"
        else:
            api._uid_migrator = None
        assert await _scan(api, uid, **kwargs) == {"ok": True}
        assert not _writes(state)

    @pytest.mark.asyncio
    async def test_offline_replay_runs_migration_before_sending_scan(self, migration_api):
        api, state = migration_api
        state["offline"] = True
        assert await _scan(api) is None
        assert len(api._buffer) == 1
        state["offline"] = False
        await api._flush_buffer()
        assert not api._buffer
        assert len(_writes(state)) == 1
        assert state["requests"][-1].url.path.endswith("/nfc/tag-scanned")

    @pytest.mark.asyncio
    async def test_uncertain_patch_is_reread_not_blindly_repeated(self, migration_api):
        api, state = migration_api
        state["timeout_after_commit"] = True
        assert await _scan(api) is None
        assert not any(r.method == "POST" for r in state["requests"])
        assert state["rows"][0]["tag_uid"] == "5386E308B50001"
        await api._flush_buffer()
        assert not api._buffer
        assert len(_writes(state)) == 1
        assert state["requests"][-1].method == "POST"

    @pytest.mark.asyncio
    async def test_patch_failure_preserves_binding_and_defers_scan(self, migration_api):
        api, state = migration_api
        state["patch_status"] = 403
        assert await _scan(api) is None
        assert state["rows"][0]["tag_uid"] == "885386E3"
        assert not any(r.method == "POST" for r in state["requests"])
        assert len(api._buffer) == 1

    @pytest.mark.asyncio
    async def test_unverified_patch_never_reports_successful_scan(self, migration_api):
        api, state = migration_api
        state["ignore_patch"] = True
        assert await _scan(api) is None
        assert not any(r.method == "POST" for r in state["requests"])
        assert not api._buffer

    @pytest.mark.asyncio
    async def test_journal_failure_prevents_database_write(self, migration_api, tmp_path):
        api, state = migration_api
        api._uid_migrator.journal = tmp_path / "missing" / "audit.jsonl"
        assert await _scan(api) is None
        assert not _writes(state)
        assert len(api._buffer) == 1

    @pytest.mark.asyncio
    async def test_buffer_conflict_does_not_block_other_events(self, migration_api):
        api, state = migration_api
        state["offline"] = True
        await _scan(api)
        await api.tag_removed("dev-1", "5386E308B50001")
        state["offline"] = False
        state["rows"].append({**state["rows"][0], "id": 13})
        await api._flush_buffer()
        assert not api._buffer
        assert not _writes(state)
        posts = [r for r in state["requests"] if r.method == "POST"]
        assert posts[-1].url.path.endswith("/nfc/tag-removed")

    @pytest.mark.asyncio
    async def test_failed_scan_post_does_not_repeat_committed_migration(self, migration_api):
        api, state = migration_api
        state["post_status"] = 503
        await _scan(api)
        assert len(api._buffer) == 1
        state["post_status"] = 200
        await api._flush_buffer()
        assert not api._buffer
        assert len(_writes(state)) == 1
