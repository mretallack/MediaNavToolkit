"""Tests for api/market.py."""

import httpx
import pytest
import respx

from medianav_toolbox.api.client import NaviExtrasClient
from medianav_toolbox.api.market import MarketAPI
from medianav_toolbox.auth import AuthenticationError
from medianav_toolbox.models import Credentials, DeviceInfo, DriveInfo, ServiceEndpoints, Session

ENDPOINTS = ServiceEndpoints(index_v3="https://zippy.naviextras.com/services/index/rest/3")
DEVICE = DeviceInfo(appcid=0x42000B53, brand_md5="abc123", raw_data=b"\x00" * 268)
CREDS = Credentials(username="test@example.com", password="pass123")
BASE = ENDPOINTS.index_v3


def _market(client, session=None):
    return MarketAPI(client, ENDPOINTS, session)


@respx.mock
def test_login_success():
    route = respx.post(f"{BASE}/login").mock(
        return_value=httpx.Response(
            200, content=b"ok", headers={"set-cookie": "JSESSIONID=abc.app1; Path=/"}
        )
    )
    with NaviExtrasClient() as client:
        m = _market(client)
        session = m.login(CREDS, DEVICE)
    assert session.is_authenticated


@respx.mock
def test_login_bad_credentials():
    respx.post(f"{BASE}/login").mock(return_value=httpx.Response(401, text="Unauthorized"))
    with NaviExtrasClient() as client:
        m = _market(client)
        with pytest.raises(AuthenticationError, match="401"):
            m.login(CREDS, DEVICE)


@respx.mock
def test_login_sends_full_auth():
    route = respx.post(f"{BASE}/login").mock(return_value=httpx.Response(200, content=b"ok"))
    session = Session(jsessionid="existing")
    with NaviExtrasClient() as client:
        m = _market(client, session)
        m.login(CREDS, DEVICE)
    # full-auth should include Cookie but NOT X-Auth-Token
    req = route.calls[0].request
    assert "JSESSIONID" in req.headers.get("cookie", "")


@respx.mock
def test_send_drives():
    respx.post(f"{BASE}/senddrives").mock(return_value=httpx.Response(200, content=b"ok"))
    with NaviExtrasClient() as client:
        m = _market(client, Session(jsessionid="sess1"))
        result = m.send_drives(
            [DriveInfo(drive_path="/media/usb", free_space=1000, total_space=4000)]
        )
    assert result["status"] == 200


@respx.mock
def test_send_fingerprint():
    respx.post(f"{BASE}/sendfingerprint").mock(return_value=httpx.Response(200, content=b"ok"))
    with NaviExtrasClient() as client:
        m = _market(client, Session(jsessionid="sess1"))
        result = m.send_fingerprint("aabbccdd")
    assert result["status"] == 200


@respx.mock
def test_get_process():
    respx.post(f"{BASE}/getprocess").mock(return_value=httpx.Response(200, content=b"\x00"))
    with NaviExtrasClient() as client:
        m = _market(client, Session(jsessionid="sess1"))
        info = m.get_process()
    assert info.process_id == 0  # placeholder until igo-binary parsing done


@respx.mock
def test_send_process_status():
    respx.post(f"{BASE}/sendprocessstatus").mock(return_value=httpx.Response(200, content=b"ok"))
    with NaviExtrasClient() as client:
        m = _market(client, Session(jsessionid="sess1"))
        result = m.send_process_status(1, "downloading", 50)
    assert result["status"] == 200


@respx.mock
def test_send_backups():
    respx.post(f"{BASE}/sendbackups").mock(return_value=httpx.Response(200, content=b"ok"))
    with NaviExtrasClient() as client:
        m = _market(client, Session(jsessionid="sess1"))
        result = m.send_backups([])
    assert result["status"] == 200


@respx.mock
def test_send_error():
    respx.post(f"{BASE}/senderror").mock(return_value=httpx.Response(200, content=b"ok"))
    with NaviExtrasClient() as client:
        m = _market(client, Session(jsessionid="sess1"))
        result = m.send_error(42, "test error")
    assert result["status"] == 200


@respx.mock
def test_send_md5():
    respx.post(f"{BASE}/sendmd5").mock(return_value=httpx.Response(200, content=b"ok"))
    with NaviExtrasClient() as client:
        m = _market(client, Session(jsessionid="sess1"))
        result = m.send_md5({"file.dat": "abc123"})
    assert result["status"] == 200


@respx.mock
def test_get_settings():
    respx.post(f"{BASE}/settings").mock(return_value=httpx.Response(200, content=b"ok"))
    with NaviExtrasClient() as client:
        m = _market(client, Session(jsessionid="sess1"))
        result = m.get_settings()
    assert result["status"] == 200


@respx.mock
def test_jsessionid_captured_from_response():
    respx.post(f"{BASE}/senddrives").mock(
        return_value=httpx.Response(
            200, content=b"ok", headers={"set-cookie": "JSESSIONID=new123; Path=/"}
        )
    )
    with NaviExtrasClient() as client:
        m = _market(client, Session())
        m.send_drives([])
    assert m.session.jsessionid == "new123"
