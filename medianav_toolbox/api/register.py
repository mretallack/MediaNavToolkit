"""Device registration and delegator service.

Ref: toolbox.md §2 (wire protocol), §8 (register service), §14 (delegator)

Register endpoints (on {register_url}):
  /device                      — register device (RANDOM mode)
  /delegator                   — get head unit credentials (DEVICE mode)
  /get_device_model_list       — get model list
  /get_device_descriptor_list  — get descriptors
  /devinfo                     — get device info
  /registerdeviceandunbind     — register + unbind previous
"""

from medianav_toolbox.api.client import NaviExtrasClient
from medianav_toolbox.api.igo_binary import decode_model_list_response
from medianav_toolbox.igo_parser import parse_register_response
from medianav_toolbox.igo_serializer import build_credential_block
from medianav_toolbox.models import (
    DeviceCredentials,
    DeviceInfo,
    RegisterResult,
    ServiceEndpoints,
)
from medianav_toolbox.protocol import SVC_REGISTER, build_request, parse_response
from medianav_toolbox.wire_codec import (
    build_register_device_body,
    encode_int32,
    encode_int64,
    encode_string,
)

IGO_BINARY = "application/vnd.igo-binary; v=1"
# Wire protocol requests must NOT include Content-Type (server returns 500).
# Only use Content-Type for raw igo-binary (non-wire-protocol) requests.
WIRE_HEADERS = {"User-Agent": "DaciaAutomotive-Toolbox-2026041167"}


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
    resp = client.post(url, content=wire, headers=WIRE_HEADERS)

    if resp.status_code == 409:
        raise RuntimeError(
            "Device already registered (HTTP 409). Use cached credentials or a new SWID."
        )
    if resp.status_code != 200:
        raise RuntimeError(f"Registration failed: HTTP {resp.status_code}")

    decrypted = parse_response(resp.content, seed)
    parsed = parse_register_response(decrypted)

    return DeviceCredentials(
        name=bytes.fromhex(parsed["name"]),
        code=parsed["code"],
        secret=parsed["secret"],
    )


def register_hu_device(
    client: NaviExtrasClient,
    endpoints: ServiceEndpoints,
    tb_creds: "DeviceCredentials | None" = None,
    brand_name: str = "DaciaAutomotive",
    model_name: str = "DaciaAutomotiveDeviceCY20_ULC4dot5",
    swid: str = "CK-A80R-YEC3-MYXL-18LN",
    imei: str = "32483158423731362D42323938353431",
    igo_version: str = "9.12.179.821558",
    appcid: int = 0x42000B53,
    uniq_id: str = "",
) -> DeviceCredentials | None:
    """Register the head unit device with the server.

    Uses DEVICE mode with toolbox credentials (tb_code/tb_secret) when
    tb_creds is provided. Falls back to RANDOM mode if no credentials.

    The Toolbox calls RegisterDevice twice:
    1. First call (RANDOM mode) — registers the PC toolbox itself
    2. Second call (DEVICE mode) — registers the head unit device

    The second call must use DEVICE mode with the toolbox credentials
    obtained from the first registration. Without this, the server
    returns 409 and the 0x68 delegation flow won't work.

    Returns None if already registered (409).
    """
    from medianav_toolbox.igo_serializer import build_credential_block

    body = build_register_device_body(
        brand_name=brand_name,
        model_name=model_name,
        swid=swid,
        imei=imei,
        igo_version=igo_version,
        first_use=0,
        appcid=appcid,
        uniq_id=uniq_id,
    )

    if tb_creds is not None:
        # DEVICE mode: query has raw tb_name, body encrypted with tb_secret
        query = bytes([0x40, 0x80]) + tb_creds.name
        wire = build_request(
            query=query,
            body=body,
            service_minor=SVC_REGISTER,
            code=tb_creds.code,
            secret=tb_creds.secret,
        )
    else:
        # RANDOM mode fallback
        seed = _random_seed()
        wire = build_request(
            query=b"",
            body=body,
            service_minor=SVC_REGISTER,
            code=seed,
            secret=seed,
        )
    resp = client.post(
        f"{endpoints.register}/device",
        content=wire,
        headers=WIRE_HEADERS,
    )
    if resp.status_code == 409:
        return None  # Already registered
    if resp.status_code != 200:
        raise RuntimeError(f"HU device registration failed: HTTP {resp.status_code}")

    decrypt_key = tb_creds.secret if tb_creds is not None else seed
    decrypted = parse_response(resp.content, decrypt_key)
    parsed = parse_register_response(decrypted)
    return DeviceCredentials(
        name=bytes.fromhex(parsed["name"]),
        code=parsed["code"],
        secret=parsed["secret"],
    )


def _random_seed() -> int:
    """Generate a RANDOM mode seed from current time (matches DLL behavior)."""
    import time

    M = 0xFFFFFFFF
    t = int(time.time())
    t_lo = t & M
    esi = (t_lo >> 11) & M
    ecx = (t_lo << 21) & M
    edi = (t_lo ^ ecx) & M
    ecx2 = (esi >> 3) & M
    edi2 = (edi ^ ecx2) & M
    ecx3 = ((esi << 4) | (edi2 >> 28)) & M
    eax = (edi2 << 4) & M
    return (((ecx3 ^ esi) & M) << 32) | ((eax ^ edi2) & M)


def get_delegator_credentials(
    client: NaviExtrasClient,
    endpoints: ServiceEndpoints,
    creds: DeviceCredentials,
    brand_name: str = "DaciaAutomotive",
    model_name: str = "DaciaAutomotiveDeviceCY20_ULC4dot5",
    swid: str = "CK-A80R-YEC3-MYXL-18LN",
    imei: str = "32483158423731362D42323938353431",
    igo_version: str = "9.12.179.821558",
    appcid: int = 0x42000B53,
    serial: str = "",
    vin: str = "UU1DJF00869579646",
    first_use: int = 0x63AAF600,
) -> DeviceCredentials:
    """Get head unit credentials via the delegator endpoint (DEVICE mode).

    Uses the toolbox credentials to authenticate, returns a separate set of
    credentials for the head unit device. These are needed for senddevicestatus.

    From XML dump (session 69BACB73, step 8):
      POST /services/register/rest/1/delegator
      Body type: RegisterDeviceArg with Vin field (not UniqId)

    Ref: toolbox.md §14
    """
    # Vin is sent as raw ASCII (not hex-encoded)
    body = (
        b"\x1e\x00"
        + encode_string(brand_name)
        + encode_string(model_name)
        + encode_string(swid)
        + encode_string(imei)
        + encode_string(igo_version)
        + encode_int64(first_use << 32)  # timestamp in upper 32 bits
        + encode_int32(appcid)
        + encode_string(vin)
        + b"\x00\x01\x8b\xb5"  # trailing bytes (device SKU/serial)
    )
    cred_block = build_credential_block(creds.name)
    query = bytes([0xC4, 0x20]) + cred_block
    wire = build_request(
        query=query,
        body=body,
        service_minor=SVC_REGISTER,
        code=creds.code,
        secret=creds.secret,
    )

    resp = client.post(
        f"{endpoints.register}/delegator",
        content=wire,
        headers=WIRE_HEADERS,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"Delegator failed: HTTP {resp.status_code}")

    decrypted = parse_response(resp.content, creds.secret)
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
