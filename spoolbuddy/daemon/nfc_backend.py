"""File/environment based NFC backend selection; no frontend or API changes."""

import os


def reader_name() -> str:
    name = os.environ.get("SPOOLBUDDY_NFC_READER", "pn5180").strip().lower()
    if name == "mfrc522":
        name = "rc522"
    if name not in ("pn5180", "rc522"):
        raise ValueError("SPOOLBUDDY_NFC_READER must be pn5180 or rc522")
    return name


def create_reader():
    # Import only the selected driver. Merely importing this module never opens GPIO/SPI.
    if reader_name() == "rc522":
        from .mfrc522 import MFRC522

        return MFRC522()
    from .pn5180 import PN5180

    return PN5180()


def diagnostic_args(command: str) -> list[str]:
    if reader_name() == "rc522":
        args = ["mfrc522_diag.py"]
        if command == "run_read_tag_diag":
            args += ["--require-tag", "--timeout", "10"]
        return args
    return ["read_tag.py" if command == "run_read_tag_diag" else "pn5180_diag.py"]
