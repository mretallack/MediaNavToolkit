"""Device registration service.

Ref: toolbox.md §2 (wire protocol), §8 (register service)

Register endpoints (on {register_url}):
  /device                      — register device (RANDOM mode)
  /get_device_model_list       — get model list
  /get_device_descriptor_list  — get descriptors
  /devinfo                     — get device info
  /registerdeviceandunbind     — register + unbind previous
"""

from medianav_toolbox.api.client import NaviExtrasClient
from medianav_toolbox.api.igo_binary import decode_model_list_response
from medianav_toolbox.igo_parser import parse_register_response
from medianav_toolbox.models import (
    DeviceCredentials,
    DeviceInfo,
    RegisterResult,
    ServiceEndpoints,
)
from medianav_toolbox.protocol import SVC_REGISTER, build_request, parse_response
from medianav_toolbox.wire_codec import build_register_device_body

IGO_BINARY = "application/vnd.igo-binary; v=1"


def register_device_wire(
    client: NaviExtrasClient,
    endpoints: ServiceEndpoints,
    brand_name: str = "DaciaAutomotive",
    model_name: str = "DaciaToolbox",
    swid: str = "",
    imei: str = "x51x4Dx30x30x30x30x31",
    igo_version: str = "9.35.2.0",
    first_use: int = 0,
    appcid: int = 0,
    uniq_id: str = "",
) -> DeviceCredentials:
    """Register device via wire protocol (RANDOM mode).

    Returns DeviceCredentials with Name, Code, Secret for authenticated calls.
    """
    body = build_register_device_body(
        brand_name=brand_name,
        model_name=model_name,
        swid=swid,
        imei=imei,
        igo_version=igo_version,
        first_use=first_use,
        appcid=appcid,
        uniq_id=uniq_id,
    )
    query = bytes([0x00, 0xCE])  # counter=0, flags=0xCE (RANDOM with body)
    wire = build_request(query=query, body=body, service_minor=SVC_REGISTER)
    seed = int.from_bytes(wire[4:12], "big")

    url = f"{endpoints.register}/device"
    resp = client.post(url, content=wire, headers={"Content-Type": IGO_BINARY})

    if resp.status_code != 200:
        raise RuntimeError(f"Registration failed: HTTP {resp.status_code}")

    decrypted = parse_response(resp.content, seed)
    parsed = parse_register_response(decrypted)

    return DeviceCredentials(
        name=bytes.fromhex(parsed["name"]),
        code=parsed["code"],
        secret=parsed["secret"],
    )


# --- JSON/raw fallback endpoints (existing functionality) ---


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
    """Get device descriptors for a device."""
    url = f"{endpoints.register}/get_device_descriptor_list"
    resp = client.post(url, content=device.raw_data, headers={"Content-Type": IGO_BINARY})
    return {"status": resp.status_code, "body": resp.content}


def get_device_info(
    client: NaviExtrasClient, endpoints: ServiceEndpoints, device: DeviceInfo
) -> dict:
    """Get device info by sending device data to /devinfo."""
    url = f"{endpoints.register}/devinfo"
    resp = client.post(url, content=device.raw_data, headers={"Content-Type": IGO_BINARY})
    return {"status": resp.status_code, "body": resp.content}


def register_device(
    client: NaviExtrasClient, endpoints: ServiceEndpoints, device: DeviceInfo
) -> RegisterResult:
    """Register device via /device endpoint (raw bytes, legacy)."""
    url = f"{endpoints.register}/device"
    resp = client.post(url, content=device.raw_data, headers={"Content-Type": IGO_BINARY})
    if resp.status_code == 200:
        return RegisterResult(success=True, device_id=device.appcid)
    return RegisterResult(success=False, message=f"HTTP {resp.status_code}")


def register_device_unbind(
    client: NaviExtrasClient, endpoints: ServiceEndpoints, device: DeviceInfo
) -> RegisterResult:
    """Register device + unbind previous via /registerdeviceandunbind."""
    url = f"{endpoints.register}/registerdeviceandunbind"
    resp = client.post(url, content=device.raw_data, headers={"Content-Type": IGO_BINARY})
    if resp.status_code == 200:
        return RegisterResult(success=True, device_id=device.appcid)
    return RegisterResult(success=False, message=f"HTTP {resp.status_code}")
