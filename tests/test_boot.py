"""Tests for api/boot.py."""

import json
from pathlib import Path

import httpx
import respx

from medianav_toolbox.api.boot import boot
from medianav_toolbox.api.client import NaviExtrasClient
from medianav_toolbox.config import Config

DATA_DIR = Path(__file__).parent / "data"


def _boot_json():
    return json.loads((DATA_DIR / "boot_response_v2.json").read_text())


@respx.mock
def test_boot_success():
    respx.get("https://zippy.naviextras.com/services/index/rest/2/boot").mock(
        return_value=httpx.Response(200, json=_boot_json())
    )
    with NaviExtrasClient() as client:
        endpoints = boot(client)
    assert endpoints.index_v2
    assert "naviextras.com" in endpoints.index_v2


@respx.mock
def test_boot_parses_all_services():
    respx.get("https://zippy.naviextras.com/services/index/rest/2/boot").mock(
        return_value=httpx.Response(200, json=_boot_json())
    )
    with NaviExtrasClient() as client:
        ep = boot(client)
    assert ep.register
    assert ep.selfie
    assert ep.mobile


@respx.mock
def test_boot_network_error():
    respx.get("https://zippy.naviextras.com/services/index/rest/2/boot").mock(
        side_effect=httpx.ConnectError("refused")
    )
    cfg = Config(max_retries=1, http_timeout=1)
    with NaviExtrasClient(cfg) as client:
        try:
            boot(client)
            assert False, "Should have raised"
        except httpx.ConnectError:
            pass


@respx.mock
def test_boot_server_error():
    respx.get("https://zippy.naviextras.com/services/index/rest/2/boot").mock(
        return_value=httpx.Response(500, text="Internal Server Error")
    )
    cfg = Config(max_retries=1, http_timeout=1)
    with NaviExtrasClient(cfg) as client:
        try:
            resp = boot(client)
            assert False, "Should have raised"
        except httpx.HTTPStatusError:
            pass
