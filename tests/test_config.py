"""Tests for config.py."""

import os
from pathlib import Path

from medianav_toolbox.config import Config


def test_default_config():
    c = Config()
    assert c.api_base == "https://zippy.naviextras.com/services/index/rest"
    assert c.brand == "DaciaAutomotive"
    assert c.device_type == "DaciaToolbox"
    assert c.display_version == "5.28.2026041167"
    assert c.user_agent == "WinHTTP ToolBox/1.0"
    assert c.max_retries == 3


def test_config_from_env(monkeypatch):
    monkeypatch.setenv("NAVIEXTRAS_CACHE_DIR", "/tmp/test_cache")
    monkeypatch.setenv("NAVIEXTRAS_HTTP_TIMEOUT", "60")
    c = Config.from_env()
    assert c.cache_dir == Path("/tmp/test_cache")
    assert c.http_timeout == 60
    # Defaults preserved
    assert c.brand == "DaciaAutomotive"


def test_config_env_override_api_base(monkeypatch):
    monkeypatch.setenv("NAVIEXTRAS_API_BASE", "https://test.example.com/api")
    c = Config.from_env()
    assert c.api_base == "https://test.example.com/api"


def test_config_missing_env_uses_defaults(monkeypatch):
    monkeypatch.delenv("NAVIEXTRAS_CACHE_DIR", raising=False)
    monkeypatch.delenv("NAVIEXTRAS_API_BASE", raising=False)
    monkeypatch.delenv("NAVIEXTRAS_HTTP_TIMEOUT", raising=False)
    c = Config.from_env()
    assert c.api_base == "https://zippy.naviextras.com/services/index/rest"
    assert c.http_timeout == 30
    assert c.cache_dir == Path.home() / ".medianav-toolbox" / "download_cache"
