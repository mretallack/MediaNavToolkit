"""Tests for api/register.py."""

import httpx
import respx

from medianav_toolbox.api.client import NaviExtrasClient
from medianav_toolbox.api.register import (
    get_device_descriptor_list,
    get_device_info,
    get_device_model_list,
    register_device,
    register_device_unbind,
)
from medianav_toolbox.config import Config
from medianav_toolbox.models import DeviceInfo, ServiceEndpoints

ENDPOINTS = ServiceEndpoints(register="https://zippy.naviextras.com/services/register/rest/1")
DEVICE = DeviceInfo(appcid=0x42000B53, brand_md5="abc123", raw_data=b"\x00" * 268)


@respx.mock
def test_get_device_model_list():
    # Real response format: 80 00 05 33 2e 38 35 37 00 00 = version "3.857"
    respx.post(f"{ENDPOINTS.register}/get_device_model_list").mock(
        return_value=httpx.Response(
            200,
            content=b"\x80\x00\x053.857\x00\x00",
            headers={"content-type": "application/vnd.igo-binary; v=1"},
        )
    )
    with NaviExtrasClient() as client:
        version = get_device_model_list(client, ENDPOINTS)
    assert version == "3.857"


@respx.mock
def test_get_device_descriptor_list():
    respx.post(f"{ENDPOINTS.register}/get_device_descriptor_list").mock(
        return_value=httpx.Response(417, text="")
    )
    with NaviExtrasClient() as client:
        result = get_device_descriptor_list(client, ENDPOINTS, DEVICE)
    assert result["status"] == 417


@respx.mock
def test_get_device_info():
    respx.post(f"{ENDPOINTS.register}/devinfo").mock(return_value=httpx.Response(412, text=""))
    with NaviExtrasClient() as client:
        result = get_device_info(client, ENDPOINTS, DEVICE)
    assert result["status"] == 412


@respx.mock
def test_register_device_success():
    respx.post(f"{ENDPOINTS.register}/device").mock(
        return_value=httpx.Response(200, content=b"\x00")
    )
    with NaviExtrasClient() as client:
        result = register_device(client, ENDPOINTS, DEVICE)
    assert result.success is True
    assert result.device_id == 0x42000B53


@respx.mock
def test_register_device_failure():
    respx.post(f"{ENDPOINTS.register}/device").mock(return_value=httpx.Response(417, text=""))
    with NaviExtrasClient() as client:
        result = register_device(client, ENDPOINTS, DEVICE)
    assert result.success is False
    assert "417" in result.message


@respx.mock
def test_register_device_unbind():
    respx.post(f"{ENDPOINTS.register}/registerdeviceandunbind").mock(
        return_value=httpx.Response(200, content=b"\x00")
    )
    with NaviExtrasClient() as client:
        result = register_device_unbind(client, ENDPOINTS, DEVICE)
    assert result.success is True
