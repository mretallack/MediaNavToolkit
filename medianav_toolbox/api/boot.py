"""Boot service — discover API endpoints.

Ref: toolbox.md §5 (boot/catalog flow)
"""

from medianav_toolbox.api.client import NaviExtrasClient
from medianav_toolbox.models import ServiceEndpoints


def boot(client: NaviExtrasClient) -> ServiceEndpoints:
    """Call boot endpoint to discover service URLs.

    Uses v2 JSON API: GET {api_base}/2/boot
    Fallback: POST {api_base}/3/boot (igo-binary)
    """
    url = f"{client.config.api_base}/2/boot"
    resp = client.get(url)
    resp.raise_for_status()

    data = resp.json()
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
        # Keep highest version index if v2/v3 not explicitly set
        elif name == "index" and not endpoints.index_v2:
            endpoints.index_v2 = location

    return endpoints
