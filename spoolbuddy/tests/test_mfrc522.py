"""RC522 protocol and write safety tests with an emulated transport."""

import sys
from unittest.mock import MagicMock

import pytest
from daemon import mfrc522 as driver
from daemon.mfrc522 import MFRC522


@pytest.fixture
def reader(monkeypatch):
    monkeypatch.setattr(driver.time, "sleep", lambda _: None)
    obj = MFRC522.__new__(MFRC522)
    obj._write_reg = MagicMock()
    obj._read_reg = MagicMock(return_value=0)
    obj._request = MagicMock(return_value=True)
    return obj


def crc_frame(data):
    frame = list(data) + MFRC522._calculate_crc(data)
    return frame, len(frame) * 8


def anticollision(block):
    block = list(block)
    return [*block, block[0] ^ block[1] ^ block[2] ^ block[3]], 40


def test_crc_a_known_read_command():
    assert MFRC522._calculate_crc([0x30, 0x04]) == [0x26, 0xEE]


@pytest.mark.parametrize("uid", [b"1234", b"1234567", b"1234567890"])
def test_complete_uid_and_final_sak(reader, uid):
    blocks = []
    tail = uid
    while len(tail) > 4:
        blocks += [anticollision(b"\x88" + tail[:3]), crc_frame([4])]
        tail = tail[3:]
    blocks += [anticollision(tail), crc_frame([0])]
    reader._communicate = MagicMock(side_effect=blocks)
    assert reader.activate_type_a() == (uid, 0)
    selects = [call.args[1][0] for call in reader._communicate.call_args_list]
    assert selects == [x for x in (0x93, 0x95, 0x97)[: (len(uid) - 1) // 3] for _ in range(2)]


@pytest.mark.parametrize("block,sak", [(b"1234", 4), (b"\x88123", 0)])
def test_inconsistent_cascade_is_rejected(reader, block, sak):
    reader._communicate = MagicMock(side_effect=[anticollision(block), crc_frame([sak])])
    assert reader.activate_type_a() is None


def test_bad_bcc_is_rejected(reader):
    reader._communicate = MagicMock(return_value=([1, 2, 3, 4, 0], 40))
    assert reader.activate_type_a() is None


def test_bad_response_crc_is_rejected(reader):
    reader._communicate = MagicMock(return_value=([0, 0, 0], 24))
    assert reader._exchange([0x93, 0x70], 1) is None


def test_mifare_auth_uses_final_four_uid_bytes(reader):
    reader._communicate = MagicMock(return_value=([], 0))
    reader._read_reg.return_value = 8
    assert reader.mfc_authenticate(4, b"123456", b"abcdefg")
    assert reader._communicate.call_args.args[1][-4:] == list(b"defg")


@pytest.mark.parametrize(
    "response,expected", [(None, False), (([0], 4), False), (([10], 8), False), (([], 0), False), (([10], 4), True)]
)
def test_write_requires_exact_ack(reader, response, expected):
    reader._communicate = MagicMock(return_value=response)
    assert reader._ntag_write_page(4, b"data") is expected


@pytest.mark.parametrize("start,data", [(0, b"data"), (3, b"data"), (40, b"data"), (39, b"12345"), (4, b"")])
def test_write_rejects_reserved_pages_or_overflow(reader, start, data):
    reader._ntag_user_end_page = MagicMock(return_value=40)
    reader._ntag_write_page = MagicMock()
    assert not reader.ntag_write_pages(start, data)
    reader._ntag_write_page.assert_not_called()


@pytest.mark.parametrize("readback,expected", [(b"data", True), (b"fail", False), (None, False)])
def test_write_requires_matching_readback(reader, readback, expected):
    reader._ntag_user_end_page = MagicMock(return_value=40)
    reader._ntag_write_page = MagicMock(return_value=True)
    reader.ntag_read_pages = MagicMock(return_value=readback)
    assert reader.ntag_write_pages(4, b"data") is expected


def test_nak_stops_remaining_writes(reader):
    reader._ntag_user_end_page = MagicMock(return_value=40)
    reader._ntag_write_page = MagicMock(return_value=False)
    assert not reader.ntag_write_pages(4, b"12345678")
    reader._ntag_write_page.assert_called_once()


@pytest.mark.parametrize("storage,cc_size,end", [(0x0F, 0x12, 40), (0x11, 0x3E, 128), (0x13, 0x6D, 222)])
def test_capacity_is_bounded_by_model_and_cc(reader, storage, cc_size, end):
    reader._exchange = MagicMock(return_value=bytes.fromhex("000404020100") + bytes([storage, 3]))
    reader.ntag_read_pages = MagicMock(return_value=bytes([0xE1, 0x10, cc_size, 0]))
    assert reader._ntag_user_end_page() == end
    reader.ntag_read_pages.return_value = bytes([0xE1, 0x10, 255, 0])
    assert reader._ntag_user_end_page() == {0x0F: 40, 0x11: 130, 0x13: 226}[storage]


@pytest.mark.parametrize(
    "version,cc",
    [
        (None, b"\xe1\x10\x12\x00"),
        (bytes(8), b"\xe1\x10\x12\x00"),
        (bytes.fromhex("0004040201000f03"), b"\xe1\x10\x12\x0f"),
    ],
)
def test_unknown_or_readonly_tag_is_not_writable(reader, version, cc):
    reader._exchange = MagicMock(return_value=version)
    reader.ntag_read_pages = MagicMock(return_value=cc)
    assert reader._ntag_user_end_page() is None


def test_timeout_always_stops_command(reader):
    reader._read_reg.side_effect = lambda reg: 1 if reg == driver.COM_IRQ_REG else 0
    assert reader._communicate(driver.PCD_TRANSCEIVE, [0x26]) is None
    assert reader._write_reg.call_args.args == (driver.COMMAND_REG, driver.PCD_IDLE)


def test_bambu_auth_failure_always_clears_crypto(reader):
    reader.reactivate_card = MagicMock(return_value=(b"1234", 8))
    reader.mfc_authenticate = MagicMock(return_value=False)
    reader.stop_crypto1 = MagicMock()
    assert reader.read_bambu_tag(b"1234") is None
    reader.stop_crypto1.assert_called_once()


def test_failed_constructor_releases_gpio_and_spi(monkeypatch):
    for key in list(driver.os.environ):
        if key.startswith("SPOOLBUDDY_NFC_"):
            monkeypatch.delenv(key)
    gpio, spi, chip = MagicMock(), MagicMock(), MagicMock()
    monkeypatch.setitem(sys.modules, "gpiod", gpio)
    monkeypatch.setitem(sys.modules, "spidev", spi)
    monkeypatch.setattr(driver, "_find_gpio_chip", lambda: chip)
    monkeypatch.setattr(MFRC522, "reset", MagicMock(side_effect=OSError("SPI failed")))
    with pytest.raises(OSError, match="SPI failed"):
        MFRC522()
    spi.SpiDev.return_value.close.assert_called_once()
    chip.request_lines.return_value.release.assert_called_once()
    chip.close.assert_called_once()


@pytest.mark.parametrize("version", [0, 0xFF, 0x01])
def test_invalid_version_fails_initialization(reader, monkeypatch, version):
    monkeypatch.setitem(sys.modules, "gpiod", MagicMock())
    reader._rst_pin = 25
    reader._lines = MagicMock()
    reader._read_reg.return_value = version
    with pytest.raises(RuntimeError, match="VersionReg"):
        reader.reset()


def test_diagnostic_closes_reader_after_no_tag(monkeypatch, tmp_path):
    from scripts import mfrc522_diag as diag

    hardware = MagicMock(version=0x92)
    hardware.reactivate_card.return_value = None
    monkeypatch.setattr(driver, "MFRC522", lambda: hardware)
    clock = iter([0, 0, 2])
    monkeypatch.setattr(diag.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(diag.time, "sleep", lambda _: None)
    result = diag.main(["--require-tag", "--timeout", "1", "--env-file", str(tmp_path / "missing")])
    assert result == 2
    hardware.close.assert_called_once()


def test_diagnostic_reports_hardware_failure(monkeypatch, tmp_path):
    from scripts import mfrc522_diag as diag

    monkeypatch.setattr(driver, "MFRC522", MagicMock(side_effect=RuntimeError("no device")))
    assert diag.main(["--env-file", str(tmp_path / "missing")]) == 1


def test_diagnostic_env_reads_nfc_only_without_shell_expansion(monkeypatch, tmp_path):
    from scripts.mfrc522_diag import load_nfc_env

    monkeypatch.delenv("SPOOLBUDDY_NFC_RST_PIN", raising=False)
    monkeypatch.delenv("SPOOLBUDDY_API_KEY", raising=False)
    path = tmp_path / "test.env"
    path.write_text('SPOOLBUDDY_NFC_RST_PIN="25"\nSPOOLBUDDY_API_KEY=not-to-be-loaded\n', encoding="utf-8")
    load_nfc_env(path)
    assert driver.os.environ["SPOOLBUDDY_NFC_RST_PIN"] == "25"
    assert "SPOOLBUDDY_API_KEY" not in driver.os.environ
