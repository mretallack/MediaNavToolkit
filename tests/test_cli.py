"""Tests for CLI commands."""

from pathlib import Path

import pytest
from click.testing import CliRunner

from medianav_toolbox.cli import cli

USB_PATH = str(Path(__file__).parent.parent / "analysis" / "usb_drive" / "disk")
_usb_missing = not Path(USB_PATH).exists()


@pytest.mark.skipif(_usb_missing, reason="analysis/usb_drive/disk not available")
def test_cli_detect():
    runner = CliRunner()
    result = runner.invoke(cli, ["--usb-path", USB_PATH, "detect"])
    assert result.exit_code == 0
    assert "MediaNav device detected" in result.output
    assert "0x42000B53" in result.output


def test_cli_detect_no_usb(tmp_path):
    runner = CliRunner()
    result = runner.invoke(cli, ["--usb-path", str(tmp_path), "detect"])
    assert result.exit_code != 0


def test_cli_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "detect" in result.output
    assert "login" in result.output
    assert "catalog" in result.output
    assert "register" in result.output
    assert "updates" in result.output
    assert "sync" in result.output


def test_cli_sync_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["sync", "--help"])
    assert result.exit_code == 0
    assert "--country" in result.output
    assert "--dry-run" in result.output
