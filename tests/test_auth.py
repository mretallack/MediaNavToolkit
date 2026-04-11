"""Tests for auth.py."""

import os

import pytest

from medianav_toolbox.auth import (
    AuthenticationError,
    auth_headers,
    extract_jsessionid,
    load_credentials,
)
from medianav_toolbox.models import Session


def test_credentials_from_args():
    creds = load_credentials("user@test.com", "pass123")
    assert creds.username == "user@test.com"
    assert creds.password == "pass123"


def test_credentials_from_env(monkeypatch):
    monkeypatch.setenv("NAVIEXTRAS_USER", "env@test.com")
    monkeypatch.setenv("NAVIEXTRAS_PASS", "envpass")
    creds = load_credentials()
    assert creds.username == "env@test.com"
    assert creds.password == "envpass"


def test_credentials_args_override_env(monkeypatch):
    monkeypatch.setenv("NAVIEXTRAS_USER", "env@test.com")
    monkeypatch.setenv("NAVIEXTRAS_PASS", "envpass")
    creds = load_credentials("arg@test.com", "argpass")
    assert creds.username == "arg@test.com"
    assert creds.password == "argpass"


def test_credentials_missing(monkeypatch):
    monkeypatch.delenv("NAVIEXTRAS_USER", raising=False)
    monkeypatch.delenv("NAVIEXTRAS_PASS", raising=False)
    with pytest.raises(AuthenticationError, match="Missing credentials"):
        load_credentials()


def test_credentials_partial_missing(monkeypatch):
    monkeypatch.setenv("NAVIEXTRAS_USER", "user@test.com")
    monkeypatch.delenv("NAVIEXTRAS_PASS", raising=False)
    with pytest.raises(AuthenticationError):
        load_credentials()


def test_session_headers_device_auth():
    session = Session(jsessionid="abc123", device_auth_token="tok456", is_authenticated=True)
    headers = auth_headers(session, "device-auth")
    assert headers["Cookie"] == "JSESSIONID=abc123"
    assert headers["X-Auth-Token"] == "tok456"


def test_session_headers_full_auth():
    session = Session(jsessionid="abc123")
    headers = auth_headers(session, "full-auth")
    assert "Cookie" in headers
    assert "X-Auth-Token" not in headers


def test_session_headers_no_session():
    session = Session()
    headers = auth_headers(session)
    assert headers == {}


def test_extract_jsessionid():
    assert extract_jsessionid({"JSESSIONID": "xyz.app1"}) == "xyz.app1"


def test_extract_jsessionid_none():
    assert extract_jsessionid(None) is None
    assert extract_jsessionid({}) is None
