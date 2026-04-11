"""Device registration service.

Ref: toolbox.md §8 (register service), §16 (complete path list)

Register endpoints (on {register_url}):
  /get_device_model_list       — 0x18 arg, line 66635
  /get_device_descriptor_list  — 0x20 arg, line 66215
  /devinfo                     — 0x08 arg, line 124813
  /device                      — 0x7c arg, line 138401
  /registerdeviceandunbind     — 0x7c arg, line 138307
"""

from medianav_toolbox.api.client import NaviExtrasClient
from medianav_toolbox.api.igo_binary import decode_model_list_response
from medianav_toolbox.models import DeviceInfo, RegisterResult, ServiceEndpoints


def get_device_model_list(client: NaviExtrasClient, endpoints: ServiceEndpoints) -> str | None:
    """Get device model list version. Returns version string (e.g. '3.857')."""
    url = f"{endpoints.register}/get_device_model_list"
    resp = client.post(url, json={}, headers={"Content-Type": "application/json"})
    if resp.status_code == 200 and resp.headers.get("content-type", "").startswith(
        "application/vnd.igo-binary"
    ):
        return decode_model_list_response(resp.content)
    return None


def get_device_descriptor_list(
    client: NaviExtrasClient, endpoints: ServiceEndpoints, device: DeviceInfo
) -> dict:
    """Get device descriptors for a device. Sends device.nng data."""
    url = f"{endpoints.register}/get_device_descriptor_list"
    resp = client.post(
        url,
        content=device.raw_data,
        headers={"Content-Type": "application/vnd.igo-binary; v=1"},
    )
    return {"status": resp.status_code, "body": resp.content}


def get_device_info(
    client: NaviExtrasClient, endpoints: ServiceEndpoints, device: DeviceInfo
) -> dict:
    """Get device info by sending device data to /devinfo."""
    url = f"{endpoints.register}/devinfo"
    resp = client.post(
        url,
        content=device.raw_data,
        headers={"Content-Type": "application/vnd.igo-binary; v=1"},
    )
    return {"status": resp.status_code, "body": resp.content}


def register_device(
    client: NaviExtrasClient, endpoints: ServiceEndpoints, device: DeviceInfo
) -> RegisterResult:
    """Register device via /device endpoint."""
    url = f"{endpoints.register}/device"
    resp = client.post(
        url,
        content=device.raw_data,
        headers={"Content-Type": "application/vnd.igo-binary; v=1"},
    )
    if resp.status_code == 200:
        return RegisterResult(success=True, device_id=device.appcid)
    return RegisterResult(success=False, message=f"HTTP {resp.status_code}")


def register_device_unbind(
    client: NaviExtrasClient, endpoints: ServiceEndpoints, device: DeviceInfo
) -> RegisterResult:
    """Register device + unbind previous via /registerdeviceandunbind."""
    url = f"{endpoints.register}/registerdeviceandunbind"
    resp = client.post(
        url,
        content=device.raw_data,
        headers={"Content-Type": "application/vnd.igo-binary; v=1"},
    )
    if resp.status_code == 200:
        return RegisterResult(success=True, device_id=device.appcid)
    return RegisterResult(success=False, message=f"HTTP {resp.status_code}")
