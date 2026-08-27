"""Exercise installer functions only against temporary files, never the host OS."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

INSTALLER = Path(__file__).resolve().parents[1] / "install/install.sh"


def run_shell(body, *args):
    bash = os.environ.get("BASH_EXE") or shutil.which("bash")
    if not bash:
        pytest.skip("bash not available")
    return subprocess.run(
        [
            bash,
            "-c",
            'export PATH="/usr/bin:/bin:$PATH"\nsource "$1"\n' + body,
            "test",
            INSTALLER.as_posix(),
            *map(str, args),
        ],
        text=True,
        capture_output=True,
        check=True,
    )


@pytest.mark.parametrize("selection", ["rc522", "pn5180"])
def test_boot_config_is_idempotent_and_matches_cs(tmp_path, selection):
    boot = tmp_path / "config.txt"
    boot.write_text("dtparam=spi=on\ndtparam=i2c_arm=on\ndtoverlay=spi0-0cs\n", encoding="utf-8")
    run_shell('NFC_READER="$3"\nconfigure_boot_config "$2"', boot.as_posix(), selection)
    first = boot.read_text()
    run_shell('NFC_READER="$3"\nconfigure_boot_config "$2"', boot.as_posix(), selection)
    assert boot.read_text() == first
    assert ("dtoverlay=spi0-0cs" in first.splitlines()) == (selection == "pn5180")
    assert "dtparam=spi=on" in first


def test_existing_reader_and_pin_settings_survive_reinstall(tmp_path):
    spoolbuddy = tmp_path / "spoolbuddy"
    spoolbuddy.mkdir()
    env = spoolbuddy / ".env"
    env.write_text('SPOOLBUDDY_NFC_READER="rc522"\nSPOOLBUDDY_NFC_RST_PIN=25\n', encoding="utf-8")
    run_shell(
        """
INSTALL_PATH="$2"
NFC_READER=""
resolve_nfc_reader
chown() { :; }
chgrp() { :; }
chmod() { :; }
BAMBUDDY_URL="http://example.invalid"
API_KEY="test-key"
create_spoolbuddy_env
""",
        tmp_path.as_posix(),
    )
    assert "SPOOLBUDDY_NFC_READER=rc522" in env.read_text()
    assert "SPOOLBUDDY_NFC_RST_PIN=25" in env.read_text()


def test_unknown_reader_rejected(tmp_path):
    with pytest.raises(subprocess.CalledProcessError):
        run_shell('INSTALL_PATH="$2"\nNFC_READER=wrong\nresolve_nfc_reader', tmp_path.as_posix())
