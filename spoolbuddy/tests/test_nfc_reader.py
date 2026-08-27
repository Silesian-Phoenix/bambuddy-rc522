"""Backend selection and the NFC event contract, without GPIO/SPI hardware."""

import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from daemon import nfc_backend, nfc_reader
from daemon.nfc_reader import NFCReader, NFCState


@pytest.mark.parametrize("selection,expected", [(None, "pn5180"), (" RC522 ", "rc522"), ("MFRC522", "rc522")])
def test_factory_imports_only_selected_driver(monkeypatch, selection, expected):
    monkeypatch.delenv("SPOOLBUDDY_NFC_READER", raising=False)
    if selection is not None:
        monkeypatch.setenv("SPOOLBUDDY_NFC_READER", selection)
    pn, rc = MagicMock(), MagicMock()
    monkeypatch.setitem(sys.modules, "daemon.pn5180", SimpleNamespace(PN5180=pn))
    monkeypatch.setitem(sys.modules, "daemon.mfrc522", SimpleNamespace(MFRC522=rc))
    reader = nfc_backend.create_reader()
    selected, other = (rc, pn) if expected == "rc522" else (pn, rc)
    assert reader is selected.return_value
    other.assert_not_called()


def test_invalid_selection_fails_before_hardware(monkeypatch):
    monkeypatch.setenv("SPOOLBUDDY_NFC_READER", "typo")
    factory = MagicMock()
    monkeypatch.setattr(nfc_reader, "create_reader", factory)
    with pytest.raises(ValueError, match="SPOOLBUDDY_NFC_READER"):
        NFCReader()
    factory.assert_not_called()


@pytest.fixture
def reader(monkeypatch):
    monkeypatch.setenv("SPOOLBUDDY_NFC_READER", "rc522")
    monkeypatch.setattr(nfc_reader.time, "sleep", lambda _: None)
    hardware = MagicMock()
    hardware.activate_type_a.return_value = None
    monkeypatch.setattr(nfc_reader, "create_reader", lambda: hardware)
    return NFCReader(), hardware


def test_rc522_initialization_and_presence_removal(reader):
    wrapper, hardware = reader
    assert wrapper.reader_type == "MFRC522"
    hardware.load_rf_config.assert_not_called()
    uid = bytes.fromhex("04112233445566")
    hardware.activate_type_a.return_value = (uid, 0)
    event, data = wrapper.poll()
    assert event == "tag_detected" and data["tag_uid"] == uid.hex().upper()
    assert wrapper.poll() == ("none", None)
    hardware.activate_type_a.return_value = None
    for _ in range(nfc_reader.MISS_THRESHOLD - 1):
        assert wrapper.poll() == ("none", None)
    assert wrapper.poll() == ("tag_removed", {"tag_uid": uid.hex().upper()})
    assert wrapper.state == NFCState.IDLE


def test_pn5180_default_keeps_rf_initialization(monkeypatch):
    monkeypatch.delenv("SPOOLBUDDY_NFC_READER", raising=False)
    monkeypatch.setattr(nfc_reader.time, "sleep", lambda _: None)
    hardware = MagicMock()
    monkeypatch.setattr(nfc_reader, "create_reader", lambda: hardware)
    wrapper = NFCReader()
    assert wrapper.reader_type == "PN5180"
    hardware.load_rf_config.assert_called_once_with(0, 0x80)
    hardware.set_transceive_mode.assert_called_once()


def test_close_is_idempotent_and_poll_does_not_reopen(reader):
    wrapper, hardware = reader
    wrapper.close()
    wrapper.close()
    assert not wrapper.ok
    assert wrapper.poll() == ("none", None)
    hardware.close.assert_called_once()
    hardware.activate_type_a.assert_not_called()


def test_failed_initialization_releases_reader(monkeypatch):
    monkeypatch.setenv("SPOOLBUDDY_NFC_READER", "rc522")
    hardware = MagicMock()
    hardware.reset.side_effect = OSError("unavailable")
    monkeypatch.setattr(nfc_reader, "create_reader", lambda: hardware)
    wrapper = NFCReader()
    assert not wrapper.ok
    hardware.close.assert_called_once()


def test_poll_error_can_recover(reader):
    wrapper, hardware = reader
    hardware.activate_type_a.side_effect = [OSError("SPI error"), None]
    assert wrapper.poll() == ("none", None)
    assert not wrapper.ok
    assert wrapper.poll() == ("none", None)
    assert wrapper.ok


def test_tag_replacement_reports_removal_before_new_uid(reader):
    wrapper, hardware = reader
    hardware.activate_type_a.side_effect = [(b"1234", 0), (b"5678", 0), (b"5678", 0)]
    assert wrapper.poll()[0] == "tag_detected"
    assert wrapper.poll() == ("tag_removed", {"tag_uid": b"1234".hex().upper()})
    assert wrapper.poll()[1]["tag_uid"] == b"5678".hex().upper()


def test_metadata_error_does_not_discard_uid(reader):
    wrapper, hardware = reader
    hardware.activate_type_a.return_value = (b"1234", 8)
    hardware.read_bambu_tag.side_effect = OSError("auth failed")
    assert wrapper.poll()[1]["tray_uuid"] is None


def test_write_rejects_tag_swap(reader):
    wrapper, hardware = reader
    hardware.activate_type_a.return_value = (b"1234567", 0)
    wrapper.poll()
    hardware.reactivate_card.return_value = (b"7654321", 0)
    assert wrapper.write_ntag(b"test")[0] is False
    hardware.ntag_write_pages.assert_not_called()


def test_write_failure_is_returned_to_daemon(reader):
    wrapper, hardware = reader
    hardware.activate_type_a.return_value = (b"1234567", 0)
    wrapper.poll()
    hardware.reactivate_card.return_value = (b"1234567", 0)
    hardware.ntag_write_pages.return_value = False
    assert wrapper.write_ntag(b"test") == (False, "Write or verification failed")
