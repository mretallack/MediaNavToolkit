"""Boot service — discover API endpoints.

Two modes:
  v2 JSON: GET {api_base}/2/boot → JSON with resources array
  v3 wire: POST {api_base}/3/boot → igo-binary via wire protocol (RANDOM mode)

Ref: toolbox.md §2 (wire protocol), §5 (boot flow)
"""

from medianav_toolbox.api.client import NaviExtrasClient
from medianav_toolbox.igo_parser import parse_boot_response
from medianav_toolbox.igo_serializer import build_boot_request_body
from medianav_toolbox.models import ServiceEndpoints
from medianav_toolbox.protocol import SVC_INDEX, build_request, parse_response


def boot(client: NaviExtrasClient) -> ServiceEndpoints:
    """Discover service URLs via v2 JSON boot (reliable fallback)."""
    url = f"{client.config.api_base}/2/boot"
    resp = client.get(url)
    resp.raise_for_status()
    return _parse_json_boot(resp.json())


def boot_v3(client: NaviExtrasClient) -> ServiceEndpoints:
    """Discover service URLs via v3 igo-binary wire protocol (RANDOM mode).

    This is the same protocol the real Toolbox uses.
    """
    query = build_boot_request_body(counter=0x06)
    wire = build_request(query=query, body=b"", service_minor=SVC_INDEX)
    seed = int.from_bytes(wire[4:12], "big")

    url = f"{client.config.api_base}/3/boot"
    resp = client.post(
        url,
        content=wire,
        headers={"Content-Type": "application/vnd.igo-binary; v=1"},
    )
    resp.raise_for_status()

    decrypted = parse_response(resp.content, seed)
    services = parse_boot_response(decrypted)
    return _services_to_endpoints(services)


def _parse_json_boot(data: dict) -> ServiceEndpoints:
    endpoints = ServiceEndpoints()
    for res in data.get("resources", []):
        name = res.get("name", "")
        version = res.get("version", "")
        location = res.get("location", "")
        if name == "index" and version == "2":
            endpoints.index_v2 = location
        elif name == "index" and version == "3":
            endpoints.index_v3 = location
        elif name == "register":
            endpoints.register = location
        elif name == "selfie":
            endpoints.selfie = location
        elif name == "mobile":
            endpoints.mobile = location
        elif name == "index" and not endpoints.index_v2:
            endpoints.index_v2 = location
    return endpoints


def _services_to_endpoints(services: dict[str, str]) -> ServiceEndpoints:
    endpoints = ServiceEndpoints()
    for name, url in services.items():
        if name == "index":
            endpoints.index_v3 = url
        elif name == "register":
            endpoints.register = url
        elif name == "selfie":
            endpoints.selfie = url
        elif name == "mobile":
            endpoints.mobile = url
    return endpoints
