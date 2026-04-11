"""Tests for api/client.py."""

import httpx
import pytest
import respx

from medianav_toolbox.api.client import NaviExtrasClient
from medianav_toolbox.config import Config


@respx.mock
def test_client_get_success():
    respx.get("https://example.com/test").mock(return_value=httpx.Response(200, json={"ok": True}))
    with NaviExtrasClient() as client:
        resp = client.get("https://example.com/test")
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}


@respx.mock
def test_client_user_agent():
    route = respx.get("https://example.com/ua").mock(return_value=httpx.Response(200))
    with NaviExtrasClient() as client:
        client.get("https://example.com/ua")
    assert route.calls[0].request.headers["user-agent"] == "WinHTTP ToolBox/1.0"


@respx.mock
def test_client_retry_on_500():
    route = respx.get("https://example.com/fail").mock(
        side_effect=[
            httpx.Response(500),
            httpx.Response(200, text="ok"),
        ]
    )
    cfg = Config(max_retries=2, http_timeout=5)
    with NaviExtrasClient(cfg) as client:
        resp = client.get("https://example.com/fail")
    assert resp.status_code == 200
    assert route.call_count == 2


@respx.mock
def test_client_retry_on_timeout():
    route = respx.get("https://example.com/slow").mock(
        side_effect=[
            httpx.ConnectError("timeout"),
            httpx.Response(200, text="ok"),
        ]
    )
    cfg = Config(max_retries=2, http_timeout=5)
    with NaviExtrasClient(cfg) as client:
        resp = client.get("https://example.com/slow")
    assert resp.status_code == 200


@respx.mock
def test_client_raises_after_max_retries():
    respx.get("https://example.com/down").mock(side_effect=httpx.ConnectError("refused"))
    cfg = Config(max_retries=2, http_timeout=5)
    with NaviExtrasClient(cfg) as client:
        with pytest.raises(httpx.ConnectError):
            client.get("https://example.com/down")


@respx.mock
def test_client_post():
    respx.post("https://example.com/data").mock(return_value=httpx.Response(200, text="ok"))
    with NaviExtrasClient() as client:
        resp = client.post("https://example.com/data", json={"a": 1})
    assert resp.status_code == 200
