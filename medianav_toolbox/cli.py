"""CLI commands for MediaNav Toolbox."""

import os
import sys

import click
from rich.console import Console
from rich.table import Table

console = Console()


@click.group()
@click.option(
    "--usb-path", envvar="NAVIEXTRAS_USB_PATH", default=".", help="Path to MediaNav USB drive"
)
@click.pass_context
def cli(ctx, usb_path):
    """MediaNav Toolbox — update your Dacia MediaNav head unit from Linux."""
    ctx.ensure_object(dict)
    ctx.obj["usb_path"] = usb_path


@cli.command()
@click.pass_context
def detect(ctx):
    """Detect MediaNav USB drive and show device info."""
    from pathlib import Path

    from medianav_toolbox.device import detect_drive, read_device_status, read_installed_content

    usb = Path(ctx.obj["usb_path"])
    device = detect_drive(usb)
    if device is None:
        console.print(f"[red]No valid MediaNav drive found at {usb}[/red]")
        sys.exit(1)

    console.print(f"[green]MediaNav device detected[/green]")
    console.print(f"  AppCID:    0x{device.appcid:08X}")
    console.print(f"  BrandMD5:  {device.brand_md5}")
    console.print(f"  Drive:     {device.drive_path}")

    try:
        status = read_device_status(usb)
        console.print(
            f"  Free:      {status.free_space / 1e9:.1f} GB / {status.total_space / 1e9:.1f} GB"
        )
        console.print(f"  OS:        {status.os_version}")
    except FileNotFoundError:
        pass

    installed = read_installed_content(usb)
    if installed:
        console.print(f"\n  Installed content: {len(installed)} items")
        for c in installed[:10]:
            console.print(f"    {c.content_type.value:10s} {c.file_path.stem}")


@cli.command()
@click.pass_context
def catalog(ctx):
    """List installed content on USB drive."""
    from pathlib import Path

    from medianav_toolbox.api.catalog import get_installed_catalog

    usb = Path(ctx.obj["usb_path"])
    items = get_installed_catalog(usb)
    if not items:
        console.print("[yellow]No content found on USB drive[/yellow]")
        return

    table = Table(title="Installed Content")
    table.add_column("Type", style="cyan")
    table.add_column("Name")
    table.add_column("Size", justify="right")
    table.add_column("Content ID", justify="right")

    for item in items:
        size_mb = f"{item.size / 1e6:.1f} MB" if item.size else "—"
        table.add_row(item.content_type.value, item.name, size_mb, str(item.content_id))

    console.print(table)


@cli.command()
@click.pass_context
def login(ctx):
    """Test login credentials against NaviExtras API."""
    from medianav_toolbox import Toolbox

    try:
        with Toolbox(usb_path=ctx.obj["usb_path"]) as tb:
            tb.boot()
            console.print("[green]Boot successful — API endpoints discovered[/green]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@cli.command()
@click.pass_context
def sync(ctx):
    """Full sync: detect → boot → catalog."""
    from pathlib import Path

    from medianav_toolbox import Toolbox

    usb = Path(ctx.obj["usb_path"])
    try:
        with Toolbox(usb_path=str(usb)) as tb:
            console.print("Detecting device...")
            device = tb.detect_device()
            console.print(f"  AppCID: 0x{device.appcid:08X}")

            console.print("Connecting to NaviExtras...")
            tb.boot()
            console.print("[green]Connected[/green]")

            console.print("Reading installed content...")
            catalog = tb.catalog()
            console.print(f"  {len(catalog)} items installed")
    except FileNotFoundError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)
