"""Configuration defaults derived from plugin.dll reverse engineering.

Ref: toolbox.md §2.2 (plugin.dll config tree)
"""

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Config:
    """MediaNav Toolbox configuration. Defaults from plugin.dll decompilation."""

    # API endpoints (toolbox.md §2.2, line 486)
    api_base: str = "https://zippy.naviextras.com/services/index/rest"
    selfie_url: str = "https://zippy.naviextras.com/services/selfie/rest/1/update"

    # Brand identity (toolbox.md §2.2, line 630-672)
    brand: str = "DaciaAutomotive"
    device_type: str = "DaciaToolbox"
    legacy_brand: str = "Dacia"
    model_filter: str = "Dacia_ULC"

    # App identity (toolbox.md §2.2, line 770-800)
    display_version: str = "5.28.2026041167"
    user_agent: str = "WinHTTP ToolBox/1.0"

    # Timeouts
    timeout_idle_ms: int = 30000
    http_timeout: int = 30

    # Local paths
    cache_dir: Path = field(
        default_factory=lambda: Path.home() / ".medianav-toolbox" / "download_cache"
    )

    # Download settings
    max_concurrent_downloads: int = 2
    max_retries: int = 3

    @classmethod
    def from_env(cls) -> "Config":
        """Create config with overrides from environment / .env file."""
        kwargs = {}
        if v := os.environ.get("NAVIEXTRAS_CACHE_DIR"):
            kwargs["cache_dir"] = Path(v)
        if v := os.environ.get("NAVIEXTRAS_API_BASE"):
            kwargs["api_base"] = v
        if v := os.environ.get("NAVIEXTRAS_HTTP_TIMEOUT"):
            kwargs["http_timeout"] = int(v)
        return cls(**kwargs)
