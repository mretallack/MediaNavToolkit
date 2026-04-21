"""Content management: select, download, and install content updates.

The NaviExtras download flow:
1. Login → sendfingerprint → getprocess (session establishment)
2. GET /toolbox/managecontentinitwithhierarchy/install (content tree)
3. POST /rest/managecontent/supermarket/v1/updateselection (select content, get sizes)
4. GET /toolbox/managecontentconfirmselection (trigger install)
5. Wire protocol getprocess returns download tasks
6. Download files and write to USB

Ref: toolbox.md §9, captured traffic analysis
"""

from dataclasses import dataclass

import httpx

from medianav_toolbox.catalog import (
    ContentNode,
    ContentSize,
    parse_managecontent_html,
    parse_update_selection,
)
from medianav_toolbox.session import BROWSER_UA, MARKET_BASE


@dataclass
class SelectedContent:
    """Content selected for installation with size info."""

    content_id: str
    name: str
    size: int  # bytes
    release: str = ""


def _web_headers(jsessionid: str, referer: str = "") -> dict[str, str]:
    h = {
        "User-Agent": BROWSER_UA,
        "Cookie": f"JSESSIONID={jsessionid}",
    }
    if referer:
        h["Referer"] = referer
    return h


BASE_URL = MARKET_BASE.replace("/rest", "")


def get_content_tree(client: httpx.Client, jsessionid: str) -> list[ContentNode]:
    """Fetch and parse the content tree (available updates)."""
    resp = client.get(
        f"{BASE_URL}/toolbox/managecontentinitwithhierarchy/install",
        headers=_web_headers(jsessionid),
    )
    resp.raise_for_status()
    return parse_managecontent_html(resp.text)


def select_content(
    client: httpx.Client,
    jsessionid: str,
    content_ids: list[str],
) -> tuple[list[ContentSize], dict]:
    """Select content for installation and get size estimates.

    Args:
        content_ids: list of content IDs like ["1182615#1008", "1182615#1177715"]
                     Pass empty list to deselect all.
    """
    import json
    import time

    url = f"{BASE_URL}/rest/managecontent/supermarket/v1/updateselection"
    body = f"selectedIds={json.dumps(content_ids)}".encode()
    headers = {
        **_web_headers(jsessionid, f"{BASE_URL}/toolbox/managecontentinitwithhierarchy/install"),
        "Content-Type": "application/json",
        "X-Requested-With": "XMLHttpRequest",
    }

    last_exc = None
    for attempt in range(3):
        try:
            resp = client.post(url, content=body, headers=headers, timeout=30.0)
            resp.raise_for_status()
            return parse_update_selection(resp.json())
        except (httpx.TimeoutException, httpx.ConnectError, httpx.RemoteProtocolError) as e:
            last_exc = e
            if attempt < 2:
                time.sleep(2**attempt)
    raise last_exc  # type: ignore[misc]


def confirm_selection(client: httpx.Client, jsessionid: str) -> str:
    """Confirm content selection and trigger the install process.

    Returns the HTML of the confirmation page.
    The server may take a while to process, so we use a longer timeout and retry.
    """
    import time

    url = f"{BASE_URL}/toolbox/managecontentconfirmselection"
    headers = _web_headers(
        jsessionid,
        f"{BASE_URL}/toolbox/managecontentinitwithhierarchy/install",
    )

    last_exc = None
    for attempt in range(3):
        try:
            resp = client.get(url, headers=headers, timeout=60.0)
            resp.raise_for_status()
            return resp.text
        except (httpx.TimeoutException, httpx.ConnectError, httpx.RemoteProtocolError) as e:
            last_exc = e
            if attempt < 2:
                time.sleep(2**attempt)
    raise last_exc  # type: ignore[misc]


def get_available_updates(client: httpx.Client, jsessionid: str) -> list[SelectedContent]:
    """Get all available content with sizes (selects all, then deselects).

    Returns list of all installable content with their sizes.
    """
    nodes = get_content_tree(client, jsessionid)
    if not nodes:
        return []

    all_ids = [n.content_id for n in nodes]
    sizes, _ = select_content(client, jsessionid, all_ids)

    # Deselect all to avoid accidental installs
    select_content(client, jsessionid, [])

    size_map = {s.content_id: s.size for s in sizes}
    name_map = {n.content_id: n.name for n in nodes}
    release_map = {n.content_id: n.release for n in nodes}

    return [
        SelectedContent(
            content_id=s.content_id,
            name=name_map.get(s.content_id, ""),
            size=s.size,
            release=release_map.get(s.content_id, ""),
        )
        for s in sizes
    ]
