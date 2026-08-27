#!/usr/bin/env python3
"""Bounded RC522 diagnostics. Stop spoolbuddy before running this manually."""

import argparse
import os
import shlex
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def load_nfc_env(path: Path):
    """Read NFC values only; never execute/shell-source a configuration file."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        key = key.strip()
        if separator and key.startswith("SPOOLBUDDY_NFC_"):
            tokens = shlex.split(value, comments=True)
            if len(tokens) > 1:
                raise ValueError(f"Invalid value for {key}")
            os.environ.setdefault(key, tokens[0] if tokens else "")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, default=PROJECT_ROOT / ".env")
    parser.add_argument("--timeout", type=float, default=0)
    parser.add_argument("--require-tag", action="store_true")
    args = parser.parse_args(argv)
    if not 0 <= args.timeout <= 30:
        parser.error("--timeout must be between 0 and 30 seconds")
    reader = None
    try:
        load_nfc_env(args.env_file)
        from daemon.mfrc522 import MFRC522

        reader = MFRC522()
        print(f"MFRC522 VersionReg=0x{reader.version:02X}; SPI communication OK")
        if not args.require_tag:
            return 0
        deadline = time.monotonic() + (args.timeout or 10)
        while time.monotonic() < deadline:
            selected = reader.reactivate_card()
            if selected is not None:
                uid, sak = selected
                print(f"Tag UID={uid.hex().upper()}, SAK=0x{sak:02X}")
                return 0
            time.sleep(0.1)
        print("No tag detected before timeout", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"RC522 diagnostic failed: {exc}", file=sys.stderr)
        return 1
    finally:
        if reader is not None:
            reader.close()


if __name__ == "__main__":
    raise SystemExit(main())
