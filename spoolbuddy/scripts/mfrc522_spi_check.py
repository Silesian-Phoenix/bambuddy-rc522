#!/usr/bin/env python3
"""Compatibility entry point for the original RC522 SPI check."""

from mfrc522_diag import main

if __name__ == "__main__":
    raise SystemExit(main())
