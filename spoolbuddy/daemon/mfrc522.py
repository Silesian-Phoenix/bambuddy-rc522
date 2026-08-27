"""MFRC522 NFC/RFID frontend driver for SpoolBuddy.

Backend zgodny interfejsowo z PN5180, ale przeznaczony dla modułów RC522.
Obsługiwane minimum:
- ISO14443A / MIFARE Classic anticollision + select,
- MIFARE Classic Key A authentication,
- odczyt bloków Bambu przez HKDF-derived keys,
- podstawowy odczyt/zapis NTAG.
"""

import hashlib
import hmac
import logging
import os
import time

logger = logging.getLogger(__name__)


def _env_int(name: str, default: int, minimum: int = 0, maximum: int = 255) -> int:
    value = int(os.environ.get(name, str(default)))
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


# Bambu Lab MIFARE Classic key derivation constants.
BAMBU_MASTER_KEY = bytes(
    [
        0x9A,
        0x75,
        0x9C,
        0xF2,
        0xC4,
        0xF7,
        0xCA,
        0xFF,
        0x22,
        0x2C,
        0xB9,
        0x76,
        0x9B,
        0x41,
        0xBC,
        0x96,
    ]
)

BAMBU_CONTEXT = b"RFID-A\x00"
BAMBU_BLOCKS = [1, 2, 4, 5]


# MFRC522 registers.
COMMAND_REG = 0x01
COM_I_EN_REG = 0x02
DIV_I_EN_REG = 0x03
COM_IRQ_REG = 0x04
DIV_IRQ_REG = 0x05
ERROR_REG = 0x06
STATUS_1_REG = 0x07
STATUS_2_REG = 0x08
FIFO_DATA_REG = 0x09
FIFO_LEVEL_REG = 0x0A
CONTROL_REG = 0x0C
BIT_FRAMING_REG = 0x0D
COLL_REG = 0x0E

MODE_REG = 0x11
TX_MODE_REG = 0x12
RX_MODE_REG = 0x13
TX_CONTROL_REG = 0x14
TX_ASK_REG = 0x15

CRC_RESULT_REG_H = 0x21
CRC_RESULT_REG_L = 0x22

T_MODE_REG = 0x2A
T_PRESCALER_REG = 0x2B
T_RELOAD_REG_H = 0x2C
T_RELOAD_REG_L = 0x2D

VERSION_REG = 0x37


# MFRC522 commands.
PCD_IDLE = 0x00
PCD_CALC_CRC = 0x03
PCD_TRANSCEIVE = 0x0C
PCD_MF_AUTHENT = 0x0E
PCD_SOFT_RESET = 0x0F


# PICC commands.
PICC_REQA = 0x26
PICC_WUPA = 0x52
PICC_ANTICOLL_CL1 = 0x93
PICC_SELECT_CL1 = 0x93
PICC_MF_AUTH_KEY_A = 0x60
PICC_READ = 0x30
PICC_UL_WRITE = 0xA2


def hkdf_derive_keys(uid: bytes) -> bytes:
    """Wyprowadź 96 bajtów kluczy MIFARE dla 16 sektorów."""
    prk = hmac.new(BAMBU_MASTER_KEY, uid, hashlib.sha256).digest()

    okm = b""
    t = b""
    counter = 1

    while len(okm) < 96:
        t = hmac.new(prk, t + BAMBU_CONTEXT + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1

    return okm[:96]


def get_sector_key(keys: bytes, block: int) -> bytes:
    sector = block // 4
    return keys[sector * 6 : sector * 6 + 6]


def _find_gpio_chip():
    import gpiod

    for path in ["/dev/gpiochip4", "/dev/gpiochip0"]:
        try:
            chip = gpiod.Chip(path)
            if "pinctrl" in chip.get_info().label:
                return chip
            chip.close()
        except (FileNotFoundError, PermissionError, OSError):
            continue

    raise RuntimeError("No GPIO chip found")


class MFRC522:
    """RC522 with kernel CS (CE0/CE1), libgpiod v2 and bounded transactions.

    Derived from the owner's original RC522 driver. Only one tag should be
    presented at a time; collisions are rejected rather than resolved.
    """

    reader_type = "MFRC522"
    connection = "SPI"

    def __init__(self):
        import gpiod
        import spidev

        self._chip = self._lines = self._spi = None
        self._rst_pin = _env_int("SPOOLBUDDY_NFC_RST_PIN", 25, maximum=27)
        bus = _env_int("SPOOLBUDDY_NFC_SPI_BUS", 0)
        device = _env_int("SPOOLBUDDY_NFC_SPI_DEVICE", 0, maximum=1)
        speed = _env_int("SPOOLBUDDY_NFC_SPI_SPEED_HZ", 500_000, 1, 10_000_000)
        if os.environ.get("SPOOLBUDDY_NFC_NSS_PIN", "").strip():
            raise ValueError("RC522 uses hardware CS: remove SPOOLBUDDY_NFC_NSS_PIN and wire SDA/SS to CE0 or CE1")
        if self._rst_pin in (7, 8, 9, 10, 11):
            raise ValueError("RC522 RST must not overlap SPI0 pins GPIO7-11")
        try:
            self._chip = _find_gpio_chip()
            self._lines = self._chip.request_lines(
                consumer="mfrc522",
                config={
                    self._rst_pin: gpiod.LineSettings(
                        direction=gpiod.line.Direction.OUTPUT,
                        output_value=gpiod.line.Value.ACTIVE,
                    )
                },
            )
            self._spi = spidev.SpiDev()
            self._spi.open(bus, device)
            self._spi.max_speed_hz = speed
            self._spi.mode = 0
            self.reset()
        except Exception:
            self.close()
            raise
        logger.info("MFRC522 initialized (SPI%d.%d, RST GPIO%d)", bus, device, self._rst_pin)

    def close(self):
        if self._spi is not None:
            try:
                self.rf_off()
            except Exception:
                pass
        for attr, method in (("_spi", "close"), ("_lines", "release"), ("_chip", "close")):
            resource = getattr(self, attr, None)
            if resource is not None:
                try:
                    getattr(resource, method)()
                except Exception:
                    pass
                setattr(self, attr, None)

    def _read_reg(self, reg: int) -> int:
        return self._spi.xfer2([((reg << 1) & 0x7E) | 0x80, 0])[1]

    def _write_reg(self, reg: int, value: int) -> None:
        self._spi.xfer2([(reg << 1) & 0x7E, value & 0xFF])

    def _set_bit_mask(self, reg: int, mask: int) -> None:
        self._write_reg(reg, self._read_reg(reg) | mask)

    def _clear_bit_mask(self, reg: int, mask: int) -> None:
        self._write_reg(reg, self._read_reg(reg) & (~mask & 0xFF))

    def reset(self):
        import gpiod

        self._lines.set_value(self._rst_pin, gpiod.line.Value.INACTIVE)
        time.sleep(0.050)
        self._lines.set_value(self._rst_pin, gpiod.line.Value.ACTIVE)
        time.sleep(0.050)
        self._write_reg(COMMAND_REG, PCD_SOFT_RESET)
        time.sleep(0.050)
        self.version = self._read_reg(VERSION_REG)
        if self.version not in (0x90, 0x91, 0x92, 0x88):
            raise RuntimeError(f"RC522 not responding or unsupported VersionReg=0x{self.version:02X}")
        self._write_reg(T_MODE_REG, 0x8D)
        self._write_reg(T_PRESCALER_REG, 0x3E)
        self._write_reg(T_RELOAD_REG_L, 30)
        self._write_reg(T_RELOAD_REG_H, 0)
        self._write_reg(TX_MODE_REG, 0)
        self._write_reg(RX_MODE_REG, 0)
        self._write_reg(TX_ASK_REG, 0x40)
        self._write_reg(MODE_REG, 0x3D)
        self.rf_on()

    def rf_on(self):
        self._set_bit_mask(TX_CONTROL_REG, 0x03)

    def rf_off(self):
        self._clear_bit_mask(TX_CONTROL_REG, 0x03)

    def stop_crypto1(self):
        self._clear_bit_mask(STATUS_2_REG, 0x08)

    @staticmethod
    def _calculate_crc(data) -> list[int]:
        """ISO14443A CRC_A (initial value 0x6363, low byte first)."""
        crc = 0x6363
        for value in data:
            value ^= crc & 0xFF
            value ^= (value << 4) & 0xFF
            crc = ((crc >> 8) ^ (value << 8) ^ (value << 3) ^ (value >> 4)) & 0xFFFF
        return [crc & 0xFF, crc >> 8]

    def _communicate(self, command, send_data, valid_bits=0, timeout_s=0.100):
        if len(send_data) > 64:
            raise ValueError("RC522 FIFO limited to 64 bytes")
        wait_irq = 0x30 if command == PCD_TRANSCEIVE else 0x10
        self._write_reg(COMMAND_REG, PCD_IDLE)
        self._write_reg(COM_IRQ_REG, 0x7F)
        self._write_reg(FIFO_LEVEL_REG, 0x80)
        self._write_reg(BIT_FRAMING_REG, valid_bits & 7)
        for value in send_data:
            self._write_reg(FIFO_DATA_REG, value)
        self._write_reg(COMMAND_REG, command)
        try:
            if command == PCD_TRANSCEIVE:
                self._set_bit_mask(BIT_FRAMING_REG, 0x80)
            deadline = time.monotonic() + timeout_s
            while True:
                irq = self._read_reg(COM_IRQ_REG)
                if irq & wait_irq:
                    break
                if irq & 1 or time.monotonic() >= deadline:
                    return None
                time.sleep(0.001)
            # CRC is checked in software for byte frames; ACK/NAK are 4 bits.
            if self._read_reg(ERROR_REG) & 0xDB:
                return None
            if command != PCD_TRANSCEIVE:
                return [], 0
            count = self._read_reg(FIFO_LEVEL_REG)
            last_bits = self._read_reg(CONTROL_REG) & 7
            if not 0 < count <= 64:
                return None
            bits = (count - 1) * 8 + last_bits if last_bits else count * 8
            return [self._read_reg(FIFO_DATA_REG) for _ in range(count)], bits
        finally:
            self._clear_bit_mask(BIT_FRAMING_REG, 0x80)
            self._write_reg(COMMAND_REG, PCD_IDLE)

    def _request(self, command):
        self.stop_crypto1()
        result = self._communicate(PCD_TRANSCEIVE, [command], valid_bits=7, timeout_s=0.050)
        return result is not None and len(result[0]) == 2 and result[1] == 16

    def _exchange(self, frame, payload_size):
        """Send CRC_A and require a complete response with matching CRC_A."""
        result = self._communicate(PCD_TRANSCEIVE, list(frame) + self._calculate_crc(frame))
        if result is None:
            return None
        data, bits = result
        if len(data) != payload_size + 2 or bits != len(data) * 8:
            return None
        if data[-2:] != self._calculate_crc(data[:-2]):
            return None
        return bytes(data[:-2])

    def activate_type_a(self):
        self.rf_on()
        if not self._request(PICC_WUPA) and not self._request(PICC_REQA):
            return None
        uid = bytearray()
        for level, select in enumerate((0x93, 0x95, 0x97)):
            self._write_reg(COLL_REG, 0x80)
            result = self._communicate(PCD_TRANSCEIVE, [select, 0x20])
            if result is None:
                return None
            block, bits = result
            if len(block) != 5 or bits != 40:
                return None
            if block[0] ^ block[1] ^ block[2] ^ block[3] != block[4]:
                return None
            selected = self._exchange([select, 0x70, *block], 1)
            if selected is None:
                return None
            sak = selected[0]
            cascade = bool(sak & 0x04)
            if cascade:
                if block[0] != 0x88 or level == 2:
                    return None
                uid.extend(block[1:4])
            else:
                if level < 2 and block[0] == 0x88:
                    return None
                uid.extend(block[:4])
                return bytes(uid), sak
        return None

    def reactivate_card(self):
        self.rf_off()
        time.sleep(0.010)
        self.rf_on()
        time.sleep(0.020)
        return self.activate_type_a()

    def mfc_authenticate(self, block, key, uid):
        if len(key) != 6 or len(uid) not in (4, 7, 10):
            return False
        self.stop_crypto1()
        frame = [PICC_MF_AUTH_KEY_A, block, *key, *uid[-4:]]
        result = self._communicate(PCD_MF_AUTHENT, frame, timeout_s=0.300)
        return result is not None and bool(self._read_reg(STATUS_2_REG) & 8)

    def mfc_read_block(self, block):
        return self._exchange([PICC_READ, block], 16)

    def read_bambu_tag(self, uid):
        keys = hkdf_derive_keys(uid)
        blocks = {}
        current_sector = -1
        try:
            for block in BAMBU_BLOCKS:
                sector = block // 4
                if sector != current_sector:
                    selected = self.reactivate_card()
                    if selected is None or selected[0] != uid:
                        return None
                    if not self.mfc_authenticate(block, get_sector_key(keys, block), uid):
                        return None
                    current_sector = sector
                data = self.mfc_read_block(block)
                if data is None:
                    return None
                blocks[block] = data
            return blocks
        finally:
            self.stop_crypto1()

    def ntag_read_pages(self, start_page, num_pages):
        if start_page < 0 or num_pages < 0 or start_page + num_pages > 256:
            return None
        result = bytearray()
        for offset in range(0, num_pages, 4):
            data = self._exchange([PICC_READ, start_page + offset], 16)
            if data is None:
                return None
            result.extend(data[: min(4, num_pages - offset) * 4])
        return bytes(result)

    def read_ntag(self, uid):
        selected = self.reactivate_card()
        if selected is None or selected[0] != uid:
            return None
        return self.ntag_read_pages(4, 17)

    def _ntag_user_end_page(self):
        # NXP NTAG213/215/216 GET_VERSION and CC: fail closed for other tags.
        version = self._exchange([0x60], 8)
        if version is None or version[:6] != bytes.fromhex("000404020100") or version[7] != 3:
            return None
        end = {0x0F: 40, 0x11: 130, 0x13: 226}.get(version[6])
        cc = self.ntag_read_pages(3, 1)
        if end is None or cc is None or cc[0] != 0xE1 or cc[1] >> 4 != 1 or cc[3] != 0:
            return None
        return min(end, 4 + cc[2] * 2)

    def _ntag_write_page(self, page, data):
        if len(data) != 4 or not 4 <= page < 226:
            return False
        frame = [PICC_UL_WRITE, page, *data]
        response = self._communicate(PCD_TRANSCEIVE, frame + self._calculate_crc(frame))
        if response is None:
            return False
        ack, bits = response
        return bits == 4 and len(ack) == 1 and (ack[0] & 0x0F) == 0x0A

    def ntag_write_pages(self, start_page, data):
        # Never write UID, CC, lock, password or configuration pages.
        padded = bytes(data) + bytes((-len(data)) % 4)
        end = self._ntag_user_end_page()
        if not padded or end is None or start_page < 4 or start_page + len(padded) // 4 > end:
            return False
        for offset in range(0, len(padded), 4):
            if not self._ntag_write_page(start_page + offset // 4, padded[offset : offset + 4]):
                return False
            time.sleep(0.005)
        # Require actual readback; an ACK alone is not successful persistence.
        return self.ntag_read_pages(start_page, len(padded) // 4) == padded
