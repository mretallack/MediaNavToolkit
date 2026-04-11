"""Tests for CLI commands."""

from pathlib import Path

from click.testing import CliRunner

from medianav_toolbox.cli import cli

USB_PATH = str(Path(__file__).parent.parent / "analysis" / "usb_drive" / "disk")


def test_cli_detect():
    runner = CliRunner()
    result = runner.invoke(cli, ["--usb-path", USB_PATH, "detect"])
    assert result.exit_code == 0
    assert "MediaNav device detected" in result.output
    assert "0x42000B53" in result.output


def test_cli_catalog():
    runner = CliRunner()
    result = runner.invoke(cli, ["--usb-path", USB_PATH, "catalog"])
    assert result.exit_code == 0
    assert "Installed Content" in result.output


def test_cli_detect_no_usb(tmp_path):
    runner = CliRunner()
    result = runner.invoke(cli, ["--usb-path", str(tmp_path), "detect"])
    assert result.exit_code == 1
    assert "No valid MediaNav drive" in result.output
