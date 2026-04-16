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
from medianav_toolbox.session import MARKET_BASE, TOOLBOX_UA


@dataclass
class SelectedContent:
    """Content selected for installation with size info."""

    content_id: str
    name: str
    size: int  # bytes
    release: str = ""


def _web_headers(jsessionid: str) -> dict[str, str]:
    return {
        "User-Agent": TOOLBOX_UA,
        "Cookie": f"JSESSIONID={jsessionid}",
    }


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

    resp = client.post(
        f"{BASE_URL}/rest/managecontent/supermarket/v1/updateselection",
        content=f"selectedIds={json.dumps(content_ids)}".encode(),
        headers={
            **_web_headers(jsessionid),
            "Content-Type": "application/json",
            "X-Requested-With": "XMLHttpRequest",
        },
    )
    resp.raise_for_status()
    return parse_update_selection(resp.json())


def confirm_selection(client: httpx.Client, jsessionid: str) -> str:
    """Confirm content selection and trigger the install process.

    Returns the HTML of the confirmation page.
    """
    resp = client.get(
        f"{BASE_URL}/toolbox/managecontentconfirmselection",
        headers=_web_headers(jsessionid),
    )
    resp.raise_for_status()
    return resp.text


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
