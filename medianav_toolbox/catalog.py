"""Parse catalog and content data from NaviExtras HTML and wire protocol responses.

Ref: toolbox.md §9 (catalog), captured traffic analysis
"""

import re
import struct
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
    """A license entry from the licenses wire response."""

    swid: str
    lyc_file: str
    lyc_data: bytes
    timestamp: int = 0
    expiry: int = 0


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
    """Parse the licenses wire protocol response (decrypted body).

    Wire format:
        [1B presence=0x40][2B count BE]
        Entry × count:
            [1B marker=0xC0][4B timestamp BE][4B expiry BE]
            [1B swid_len][swid bytes][1B fname_len][fname bytes]
            [4B lyc_size BE][lyc_data bytes]
    """
    if len(data) < 3 or data[0] != 0x40:
        return []
    count = struct.unpack(">H", data[1:3])[0]
    off = 3
    licenses = []
    for _ in range(count):
        if off >= len(data) or data[off] != 0xC0:
            break
        off += 1
        ts = struct.unpack(">I", data[off : off + 4])[0]
        off += 4
        expiry = struct.unpack(">I", data[off : off + 4])[0]
        off += 4
        swid_len = data[off]
        off += 1
        swid = data[off : off + swid_len].decode("ascii")
        off += swid_len
        fname_len = data[off]
        off += 1
        fname = data[off : off + fname_len].decode("ascii")
        off += fname_len
        lyc_size = struct.unpack(">I", data[off : off + 4])[0]
        off += 4
        lyc_data = data[off : off + lyc_size]
        off += lyc_size
        licenses.append(
            License(swid=swid, lyc_file=fname, lyc_data=lyc_data, timestamp=ts, expiry=expiry)
        )
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
