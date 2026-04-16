"""Parse catalog and content data from NaviExtras HTML and wire protocol responses.

Ref: toolbox.md §9 (catalog), captured traffic analysis
"""

import re
from dataclasses import dataclass, field


@dataclass
class CatalogItem:
    """An item from the catalog list page."""

    package_code: int
    name: str
    release: str = ""
    css_class: str = ""  # content-osm, content-other, etc.
    provider: str = ""  # "NNG Maps" etc.


@dataclass
class ContentNode:
    """A content node from the manage-content install tree."""

    content_id: str  # e.g. "1182615#1008"
    name: str
    release: str = ""
    snapshot_code: str = ""
    selected: bool = False
    children: list["ContentNode"] = field(default_factory=list)


@dataclass
class ContentSize:
    """Content size info from updateselection API."""

    content_id: str
    size: int


@dataclass
class License:
    """A license entry from the licenses response."""

    lyc_file: str
    swid: str = ""


def parse_catalog_html(html: str) -> list[CatalogItem]:
    """Parse the /toolbox/cataloglist HTML page.

    Extracts package codes, names, releases, and content types.
    """
    items = []
    for m in re.finditer(
        r'<tr\s+id="row(\d+)"[^>]*class="([^"]*)"[^>]*>.*?</tr>',
        html,
        re.DOTALL,
    ):
        code = int(m.group(1))
        css = m.group(2)
        block = m.group(0)

        provider = ""
        pm = re.search(r'class="provider-tag">([^<]+)', block)
        if pm:
            provider = pm.group(1).strip()

        name = ""
        nm = re.search(r'class="linknoeffect[^"]*">([^<]+)', block)
        if nm:
            name = nm.group(1).strip()

        release = ""
        rm = re.search(r'class="searchableRelease"[^>]*>\s*([^<]+)', block)
        if rm:
            release = rm.group(1).strip()

        items.append(
            CatalogItem(
                package_code=code,
                name=name,
                release=release,
                css_class=css,
                provider=provider,
            )
        )
    return items


def parse_managecontent_html(html: str) -> list[ContentNode]:
    """Parse the /toolbox/managecontentinitwithhierarchy/install HTML page.

    Extracts the jstree content tree with IDs, names, releases, and snapshot codes.
    """
    nodes = []
    for m in re.finditer(
        r'<li[^>]*id="(\d+#\d+)"[^>]*>.*?</li>',
        html,
        re.DOTALL,
    ):
        content_id = m.group(1)
        block = m.group(0)

        name = ""
        nm = re.search(r'name="content_name"\s*>\s*(?:<[^>]+>)?\s*([^<]+)', block)
        if nm:
            name = nm.group(1).strip()

        release = ""
        rm = re.search(r'name="content_release">([^<]+)', block)
        if rm:
            release = rm.group(1).strip()

        snapshot = ""
        sm = re.search(r'snapshotcode="(\d+)"', block)
        if sm:
            snapshot = sm.group(1)

        selected = '"selected": true' in block or '"selected":true' in block

        nodes.append(
            ContentNode(
                content_id=content_id,
                name=name,
                release=release,
                snapshot_code=snapshot,
                selected=selected,
            )
        )
    return nodes


def parse_update_selection(data: dict) -> tuple[list[ContentSize], dict]:
    """Parse the /rest/managecontent/supermarket/v1/updateselection JSON response."""
    sizes = [
        ContentSize(content_id=item["id"], size=item["size"])
        for item in data.get("contentSize", [])
    ]
    indicator = data.get("spaceIndicator", {})
    return sizes, indicator


def parse_licenses_response(data: bytes) -> list[License]:
    """Parse the licenses wire protocol response.

    Extracts .lyc filenames and associated SWIDs.
    """
    licenses = []
    lyc_files = re.findall(rb"([A-Za-z0-9_]+\.lyc)", data)
    swids = re.findall(rb"(C[WP]-[A-Z0-9]+-[A-Z0-9]+-[A-Z0-9]+-[A-Z0-9]+-[A-Z0-9]+)", data)

    # Pair them up — each license has a SWID followed by a .lyc file
    swid_list = [s.decode() for s in swids]
    lyc_list = [f.decode() for f in lyc_files]

    for i, lyc in enumerate(lyc_list):
        swid = swid_list[i] if i < len(swid_list) else ""
        licenses.append(License(lyc_file=lyc, swid=swid))
    return licenses


def parse_senddevicestatus_response(data: bytes) -> dict:
    """Parse senddevicestatus wire protocol response.

    Returns process ID, task ID, and requested file paths.
    """
    result = {"process_id": "", "task_id": "", "requested_paths": []}

    # Extract UUIDs (process and task IDs)
    uuids = re.findall(rb"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", data)
    if len(uuids) >= 1:
        result["process_id"] = uuids[0].decode()
    if len(uuids) >= 2:
        result["task_id"] = uuids[1].decode()

    # Extract file paths (length-prefixed strings containing '/')
    paths = re.findall(rb"(primary/[A-Za-z0-9_./*]+)", data)
    result["requested_paths"] = [p.decode() for p in paths]

    return result
