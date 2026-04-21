"""CLI commands for MediaNav Toolbox.

Usage:
    medianav-toolbox detect --usb-path /media/usb
    medianav-toolbox register --usb-path /media/usb
    medianav-toolbox login --usb-path /media/usb
    medianav-toolbox catalog --usb-path /media/usb
    medianav-toolbox licenses --usb-path /media/usb
    medianav-toolbox licenses --usb-path /media/usb --install
    medianav-toolbox updates --usb-path /media/usb
"""

import os
import sys
from pathlib import Path

import click
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

load_dotenv()
console = Console()


@click.group()
@click.option(
    "--usb-path",
    envvar="NAVIEXTRAS_USB_PATH",
    default=".",
    type=click.Path(exists=True),
    help="Path to MediaNav USB drive",
)
@click.pass_context
def cli(ctx, usb_path):
    """MediaNav Toolbox — update your Dacia MediaNav head unit from Linux."""
    ctx.ensure_object(dict)
    ctx.obj["usb_path"] = Path(usb_path)


@cli.command()
@click.pass_context
def detect(ctx):
    """Detect MediaNav USB drive and show device info."""
    from medianav_toolbox.device import (
        detect_drive,
        parse_device_nng,
        read_device_status,
        validate_drive,
    )

    usb = ctx.obj["usb_path"]
    errors = validate_drive(usb)
    if errors:
        for e in errors:
            console.print(f"[red]✗ {e}[/red]")
        sys.exit(1)

    device = parse_device_nng(usb / "NaviSync" / "license" / "device.nng")
    console.print("[green]✓ MediaNav device detected[/green]")
    console.print(f"  AppCID:    0x{device.appcid:08X}")
    console.print(f"  BrandMD5:  {device.brand_md5}")

    try:
        status = read_device_status(usb)
        console.print(
            f"  Space:     {status.free_space / 1e9:.1f} GB free / {status.total_space / 1e9:.1f} GB total"
        )
        console.print(f"  OS:        {status.os_version}")
    except FileNotFoundError:
        console.print("  [dim]device_status.ini not found[/dim]")

    drive = detect_drive(usb)
    if drive:
        console.print(f"  Drive:     {drive.drive_path or 'unknown'}")


@cli.command()
@click.pass_context
def register(ctx):
    """Register device with NaviExtras (creates new credentials)."""
    import json
    import time

    from medianav_toolbox.api.boot import boot
    from medianav_toolbox.api.client import NaviExtrasClient
    from medianav_toolbox.api.register import register_device_wire
    from medianav_toolbox.config import Config
    from medianav_toolbox.device import parse_device_nng, validate_drive
    from medianav_toolbox.swid import compute_swid

    usb = ctx.obj["usb_path"]
    errors = validate_drive(usb)
    if errors:
        for e in errors:
            console.print(f"[red]✗ {e}[/red]")
        sys.exit(1)

    device = parse_device_nng(usb / "NaviSync" / "license" / "device.nng")
    creds_file = usb / ".medianav_creds.json"

    if creds_file.exists():
        console.print("[yellow]Credentials already exist. Use --force to re-register.[/yellow]")
        data = json.loads(creds_file.read_text())
        console.print(f"  Name:   {data['name']}")
        console.print(f"  Code:   {data['code']}")
        return

    console.print("Registering device...")
    swid = compute_swid(f"linux-medianav-{int(time.time())}")

    with NaviExtrasClient(Config()) as client:
        endpoints = boot(client)
        try:
            creds = register_device_wire(
                client,
                endpoints,
                swid=swid,
                appcid=device.appcid,
                uniq_id=device.brand_md5.upper(),
            )
        except RuntimeError as e:
            console.print(f"[red]✗ {e}[/red]")
            sys.exit(1)

    creds_file.write_text(
        json.dumps({"name": creds.name.hex(), "code": creds.code, "secret": creds.secret})
    )
    console.print("[green]✓ Device registered[/green]")
    console.print(f"  SWID:   {swid}")
    console.print(f"  Name:   {creds.name.hex().upper()}")
    console.print(f"  Saved:  {creds_file}")


@cli.command()
@click.pass_context
def login(ctx):
    """Authenticate with NaviExtras and show session info."""
    from medianav_toolbox.session import run_session

    usb = ctx.obj["usb_path"]
    username = os.environ.get("NAVIEXTRAS_USER", "")
    password = os.environ.get("NAVIEXTRAS_PASS", "")

    if not username or not password:
        console.print("[red]Set NAVIEXTRAS_USER and NAVIEXTRAS_PASS environment variables[/red]")
        sys.exit(1)

    console.print("Connecting...")
    result = run_session(usb, username, password)

    for step in result["steps"]:
        console.print(f"  [green]✓[/green] {step}")

    if result["errors"]:
        for e in result["errors"]:
            console.print(f"  [red]✗ {e}[/red]")
        sys.exit(1)

    session = result.get("session")
    if session and session.is_authenticated:
        console.print(f"\n[green]✓ Authenticated[/green]")
    console.print(f"  Fingerprint: {result.get('fingerprint_status', '?')}")
    console.print(f"  GetProcess:  {result.get('getprocess_status', '?')}")


@cli.command()
@click.pass_context
def catalog(ctx):
    """Show available content updates from NaviExtras."""
    from medianav_toolbox.api.client import NaviExtrasClient
    from medianav_toolbox.config import Config
    from medianav_toolbox.content import get_content_tree, select_content
    from medianav_toolbox.session import BROWSER_UA, run_session

    usb = ctx.obj["usb_path"]
    username = os.environ.get("NAVIEXTRAS_USER", "")
    password = os.environ.get("NAVIEXTRAS_PASS", "")

    if not username or not password:
        console.print("[red]Set NAVIEXTRAS_USER and NAVIEXTRAS_PASS environment variables[/red]")
        sys.exit(1)

    console.print("Logging in...")
    result = run_session(usb, username, password)
    if result["errors"]:
        for e in result["errors"]:
            console.print(f"[red]✗ {e}[/red]")
        sys.exit(1)

    jsid = result.get("web_jsessionid")
    if not jsid:
        console.print("[red]Web login failed — cannot fetch catalog[/red]")
        console.print("[dim]Check NAVIEXTRAS_USER and NAVIEXTRAS_PASS[/dim]")
        sys.exit(1)

    console.print("Fetching content tree...")
    with NaviExtrasClient(Config()) as client:
        nodes = get_content_tree(client._client, jsid)
        if not nodes:
            # Content tree requires senddevicestatus (not yet implemented).
            # Fall back to the catalog list page which shows all available content.
            from medianav_toolbox.catalog import parse_catalog_html

            resp = client.get(
                f"https://dacia-ulc.naviextras.com/toolbox/cataloglist",
                headers={"User-Agent": BROWSER_UA, "Cookie": f"JSESSIONID={jsid}"},
            )
            if resp.status_code == 200:
                items = parse_catalog_html(resp.text)
                if items:
                    table = Table(title="Available Content (Catalog)")
                    table.add_column("Content", style="cyan", max_width=50)
                    table.add_column("Release", justify="right")
                    table.add_column("Provider", style="dim")
                    table.add_column("ID", style="dim", justify="right")

                    for item in sorted(items, key=lambda i: i.name):
                        table.add_row(
                            item.name, item.release, item.provider, str(item.package_code)
                        )

                    console.print(table)
                    console.print(f"\nTotal: {len(items)} items")
                    console.print(
                        "[dim]Note: sizes unavailable — senddevicestatus not yet implemented[/dim]"
                    )
                    return

            console.print("[yellow]No content available from server[/yellow]")
            console.print(
                "[dim]The server requires senddevicestatus to show content (task 4.2)[/dim]"
            )
            return

        console.print("Getting sizes...")
        all_ids = [n.content_id for n in nodes]
        sizes, indicator = select_content(client._client, jsid, all_ids)
        # Deselect to clean up
        select_content(client._client, jsid, [])

    size_map = {s.content_id: s.size for s in sizes}

    table = Table(title="Available Content Updates")
    table.add_column("Content", style="cyan", max_width=45)
    table.add_column("Release", justify="right")
    table.add_column("Size", justify="right")
    table.add_column("ID", style="dim")

    total = 0
    for node in sorted(nodes, key=lambda n: n.name):
        size = size_map.get(node.content_id, 0)
        total += size
        size_str = f"{size / 1024 / 1024:.1f} MB" if size else "—"
        table.add_row(node.name or "(unnamed)", node.release, size_str, node.content_id)

    console.print(table)
    console.print(f"\nTotal: {len(nodes)} items, {total / 1024 / 1024 / 1024:.2f} GB")
    if indicator:
        free = indicator.get("fullSize", 0)
        console.print(f"Available space: {free / 1024 / 1024 / 1024:.2f} GB")


@cli.command()
@click.pass_context
def updates(ctx):
    """Check for available updates (quick summary)."""
    from medianav_toolbox.api.client import NaviExtrasClient
    from medianav_toolbox.config import Config
    from medianav_toolbox.content import get_content_tree
    from medianav_toolbox.session import run_session

    usb = ctx.obj["usb_path"]
    username = os.environ.get("NAVIEXTRAS_USER", "")
    password = os.environ.get("NAVIEXTRAS_PASS", "")

    if not username or not password:
        console.print("[red]Set NAVIEXTRAS_USER and NAVIEXTRAS_PASS environment variables[/red]")
        sys.exit(1)

    console.print("Checking for updates...")
    result = run_session(usb, username, password)
    if result["errors"]:
        for e in result["errors"]:
            console.print(f"[red]✗ {e}[/red]")
        sys.exit(1)

    jsid = result.get("web_jsessionid")
    if not jsid:
        console.print("[red]Web login failed[/red]")
        sys.exit(1)

    with NaviExtrasClient(Config()) as client:
        nodes = get_content_tree(client._client, jsid)

    if not nodes:
        console.print("[green]✓ No updates available[/green]")
    else:
        console.print(f"[yellow]⬆ {len(nodes)} updates available[/yellow]")
        for n in nodes[:10]:
            console.print(f"  • {n.name} ({n.release})")
        if len(nodes) > 10:
            console.print(f"  ... and {len(nodes) - 10} more")
        console.print(f"\nRun [bold]medianav-toolbox catalog[/bold] for details.")


@cli.command()
@click.option(
    "--country", "-c", multiple=True, help="Country name to update (can repeat). Omit for all."
)
@click.option("--dry-run", is_flag=True, help="Show what would be downloaded without confirming.")
@click.pass_context
def sync(ctx, country, dry_run):
    """Select content, confirm with server, and prepare USB for update.

    Selects content for installation, confirms with the NaviExtras server,
    and shows the download status. Content is downloaded by the native engine
    after confirmation.

    Examples:
        medianav-toolbox sync --usb-path /media/usb
        medianav-toolbox sync --usb-path /media/usb -c "United Kingdom" -c France
        medianav-toolbox sync --usb-path /media/usb --dry-run
    """
    from medianav_toolbox.api.client import NaviExtrasClient
    from medianav_toolbox.config import Config
    from medianav_toolbox.content import (
        confirm_selection,
        get_content_tree,
        select_content,
    )
    from medianav_toolbox.installer import check_space
    from medianav_toolbox.session import run_session

    usb = ctx.obj["usb_path"]
    username = os.environ.get("NAVIEXTRAS_USER", "")
    password = os.environ.get("NAVIEXTRAS_PASS", "")

    if not username or not password:
        console.print("[red]Set NAVIEXTRAS_USER and NAVIEXTRAS_PASS environment variables[/red]")
        sys.exit(1)

    console.print("Connecting...")
    result = run_session(usb, username, password)
    if result["errors"]:
        for e in result["errors"]:
            console.print(f"[red]✗ {e}[/red]")
        sys.exit(1)

    jsid = result.get("web_jsessionid")
    if not jsid:
        console.print("[red]Web login failed — cannot sync[/red]")
        sys.exit(1)

    with NaviExtrasClient(Config()) as client:
        hc = client._client

        # Get content tree
        console.print("Fetching content tree...")
        nodes = get_content_tree(hc, jsid)
        if not nodes:
            console.print("[green]✓ No updates available[/green]")
            return

        # Filter by country if specified
        if country:
            country_lower = {c.lower() for c in country}
            selected_nodes = [n for n in nodes if (n.name or "").lower() in country_lower]
            if not selected_nodes:
                console.print(f"[red]No matching content for: {', '.join(country)}[/red]")
                console.print("Available:")
                for n in sorted(nodes, key=lambda x: x.name or ""):
                    console.print(f"  • {n.name}")
                sys.exit(1)
        else:
            selected_nodes = nodes

        # Select content and get sizes
        selected_ids = [n.content_id for n in selected_nodes]
        console.print(f"Selecting {len(selected_ids)} items...")
        sizes, indicator = select_content(hc, jsid, selected_ids)

        size_map = {s.content_id: s.size for s in sizes}
        total_size = sum(s.size for s in sizes)

        # Show selection
        table = Table(title="Selected Content")
        table.add_column("Content", style="cyan")
        table.add_column("Size", justify="right")
        for n in sorted(selected_nodes, key=lambda x: x.name or ""):
            size = size_map.get(n.content_id, 0)
            table.add_row(n.name, f"{size / 1024 / 1024:.1f} MB")
        console.print(table)
        console.print(f"\nTotal download: {total_size / 1024 / 1024 / 1024:.2f} GB")

        if indicator:
            avail = indicator.get("fullSize", 0)
            required = indicator.get("required", 0)
            console.print(f"USB space: {avail / 1024 / 1024 / 1024:.2f} GB available")
            if required > avail:
                console.print("[red]✗ Not enough space on USB drive[/red]")
                select_content(hc, jsid, [])
                sys.exit(1)

        if dry_run:
            console.print("\n[yellow]Dry run — not confirming.[/yellow]")
            select_content(hc, jsid, [])
            return

        # Confirm
        console.print("\nConfirming selection with server...")
        confirm_selection(hc, jsid)
        console.print("[green]✓ Selection confirmed[/green]")
        console.print(
            "\n[dim]The server has queued the update. Download URLs are provided"
            "\nvia the wire protocol getprocess endpoint, which the native engine"
            "\n(nngine.dll) normally handles. Direct download from this CLI requires"
            "\ncapturing a post-confirmation getprocess response to understand the"
            "\ndownload task format."
            "\n\nTo complete the update now, run the Windows Toolbox to download,"
            "\nor capture a post-confirmation mitmproxy trace to enable direct download.[/dim]"
        )


@cli.command()
@click.option("--install", is_flag=True, help="Install licenses to USB drive.")
@click.pass_context
def licenses(ctx, install):
    """Show and install available licenses from NaviExtras.

    Fetches license files (.lyc) via the wire protocol and shows what's
    available. Use --install to write them to the USB drive.

    Examples:
        medianav-toolbox licenses --usb-path /media/usb
        medianav-toolbox licenses --usb-path /media/usb --install
    """
    from datetime import datetime

    from medianav_toolbox.session import run_session

    usb = ctx.obj["usb_path"]
    username = os.environ.get("NAVIEXTRAS_USER", "")
    password = os.environ.get("NAVIEXTRAS_PASS", "")

    if not username or not password:
        console.print("[red]Set NAVIEXTRAS_USER and NAVIEXTRAS_PASS environment variables[/red]")
        sys.exit(1)

    console.print("Connecting...")
    result = run_session(usb, username, password)
    if result["errors"]:
        for e in result["errors"]:
            console.print(f"[red]✗ {e}[/red]")
        sys.exit(1)

    lics = result.get("licenses", [])
    if not lics:
        console.print("[yellow]No licenses available from server[/yellow]")
        console.print(
            "[dim]The licenses endpoint requires 0x68 delegated credentials.\n"
            "This currently uses a replayed request that may be session-bound.\n"
            "See tasks.md 4.3.2 for details on the 0x68 delegation prefix.[/dim]"
        )
        return

    # Show available licenses
    license_dir = usb / "NaviSync" / "license"
    table = Table(title="Available Licenses")
    table.add_column("License File", style="cyan", max_width=55)
    table.add_column("SWID", style="dim")
    table.add_column("Size", justify="right")
    table.add_column("Status")

    for lic in sorted(lics, key=lambda l: l.lyc_file):
        existing = license_dir / lic.lyc_file
        if existing.exists():
            usb_size = existing.stat().st_size
            status = (
                "[green]✓ installed[/green]"
                if usb_size == len(lic.lyc_data)
                else "[yellow]⬆ update[/yellow]"
            )
        else:
            status = "[red]✗ missing[/red]"
        table.add_row(lic.lyc_file, lic.swid, f"{len(lic.lyc_data):,} B", status)

    console.print(table)

    if not install:
        console.print(f"\n{len(lics)} licenses. Use --install to write to USB.")
        return

    # Install licenses
    from medianav_toolbox.installer import install_license

    installed = 0
    for lic in lics:
        try:
            install_license(usb, lic.lyc_file, lic.lyc_data)
            console.print(f"[green]✓[/green] {lic.lyc_file} ({len(lic.lyc_data):,} B)")
            installed += 1
        except Exception as e:
            console.print(f"[red]✗ {lic.lyc_file}: {e}[/red]")

    console.print(f"\n[green]Installed {installed}/{len(lics)} licenses[/green]")


@cli.command()
@click.argument("package_code", type=int)
@click.pass_context
def buy(ctx, package_code):
    """Purchase a catalog item (free or paid) and install its license.

    Browse available items with 'catalog', then buy by package code:

        medianav-toolbox buy 61811
    """
    import re

    import httpx

    from medianav_toolbox.session import BROWSER_UA, run_session

    usb = ctx.obj["usb_path"]
    username = os.environ.get("NAVIEXTRAS_USER", "")
    password = os.environ.get("NAVIEXTRAS_PASS", "")

    if not username or not password:
        console.print("[red]Set NAVIEXTRAS_USER and NAVIEXTRAS_PASS environment variables[/red]")
        sys.exit(1)

    console.print("Connecting...")
    result = run_session(usb, username, password)
    if result["errors"]:
        for e in result["errors"]:
            console.print(f"[red]✗ {e}[/red]")
        sys.exit(1)

    jsid = result.get("web_jsessionid")
    if not jsid:
        console.print("[red]Web login failed[/red]")
        sys.exit(1)

    with httpx.Client(timeout=30, follow_redirects=True) as hc:
        h = {"User-Agent": BROWSER_UA, "Cookie": f"JSESSIONID={jsid}"}

        # 1. View catalog item
        console.print(f"Loading package {package_code}...")
        resp = hc.get(
            f"https://dacia-ulc.naviextras.com/toolbox/catalogitem?packageCode={package_code}",
            headers=h,
        )
        if resp.status_code != 200:
            console.print(f"[red]Package {package_code} not found[/red]")
            sys.exit(1)

        # Extract sales options
        form = re.search(r"<form[^>]*catalogbuyableitem[^>]*>(.*?)</form>", resp.text, re.DOTALL)
        if not form:
            console.print("[red]No purchase options available for this package[/red]")
            sys.exit(1)

        radios = re.findall(r'<input[^>]*name="salesPackageCode"[^>]*value="(\d+)"', form.group(1))
        prices = re.findall(r'<span class="price">([^<]+)</span>', form.group(1))

        if not radios:
            console.print("[red]No sales packages found[/red]")
            sys.exit(1)

        sales_code = radios[0]
        price = prices[0] if prices else "unknown"
        console.print(f"  Package: {package_code}, price: {price}")

        # 2. Submit purchase form
        resp = hc.post(
            "https://dacia-ulc.naviextras.com/toolbox/catalogbuyableitem",
            data=f"salesPackageCode={sales_code}",
            headers={**h, "Content-Type": "application/x-www-form-urlencoded"},
        )

        # 3. Check what the next step is
        btn = re.search(r'id="btn-next"[^>]*onClick="([^"]+)"', resp.text)
        if not btn:
            console.print("[red]Purchase flow failed — no next action[/red]")
            sys.exit(1)

        action = btn.group(1)
        free_match = re.search(r"getfreecontent/(\d+)", action)
        cart_match = re.search(r"addtocartonlyoneitem/(\d+)", action)

        if free_match:
            # Free item — complete purchase
            console.print("  Completing free purchase...")
            resp = hc.get(
                f"https://dacia-ulc.naviextras.com/toolbox/getfreecontent/{free_match.group(1)}",
                headers=h,
            )
            if resp.status_code == 200:
                console.print("[green]✓ Purchased![/green]")
            else:
                console.print(f"[red]Purchase failed: {resp.status_code}[/red]")
                sys.exit(1)
        elif cart_match:
            console.print(f"  This is a paid item ({price}).")
            console.print(
                "  Adding to cart — complete payment at [link]https://dacia-ulc.naviextras.com[/link]"
            )
            hc.get(
                f"https://dacia-ulc.naviextras.com/toolbox/addtocartonlyoneitem/{cart_match.group(1)}",
                headers=h,
            )
            console.print(
                "[yellow]Item added to cart. Pay via the NaviExtras website to complete.[/yellow]"
            )
            return
        else:
            console.print(f"[red]Unknown purchase action: {action[:80]}[/red]")
            sys.exit(1)

    # 4. Fetch and install the license
    console.print("Fetching license...")
    result2 = run_session(usb, username, password)
    lics = result2.get("licenses", [])
    if not lics:
        console.print("[yellow]No licenses available yet — try 'licenses' later[/yellow]")
        return

    from medianav_toolbox.installer import install_license

    installed = 0
    for lic in lics:
        existing = usb / "NaviSync" / "license" / lic.lyc_file
        if existing.exists() and existing.stat().st_size == len(lic.lyc_data):
            continue
        try:
            install_license(usb, lic.lyc_file, lic.lyc_data)
            console.print(f"[green]✓[/green] Installed {lic.lyc_file} ({len(lic.lyc_data):,} B)")
            installed += 1
        except OSError as e:
            console.print(f"[red]✗ Cannot write to USB: {e}[/red]")
            console.print("[dim]USB may be read-only. Mount with write access to install.[/dim]")
            break

    if installed:
        console.print(f"\n[green]Installed {installed} new license(s)[/green]")
    else:
        console.print("All licenses already installed.")
