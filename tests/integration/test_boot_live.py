"""Integration tests — boot service against real API."""

from medianav_toolbox.api.boot import boot


def test_boot_live(live_client):
    endpoints = boot(live_client)
    assert endpoints.index_v2
    assert "naviextras.com" in endpoints.index_v2


def test_boot_has_register(live_client):
    endpoints = boot(live_client)
    assert endpoints.register
    assert "register" in endpoints.register


def test_boot_has_selfie(live_client):
    endpoints = boot(live_client)
    assert endpoints.selfie
    assert "selfie" in endpoints.selfie


def test_boot_v3_live(live_client):
    """POST to v3 boot returns igo-binary data."""
    from medianav_toolbox.api.igo_binary import decode_boot_response

    resp = live_client.post(
        f"{live_client.config.api_base}/3/boot",
        json={},
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 200
    entries = decode_boot_response(resp.content)
    assert len(entries) >= 5
