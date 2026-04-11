"""MediaNav Toolbox — Python library for updating Dacia MediaNav head units."""

from dotenv import load_dotenv

load_dotenv()

from medianav_toolbox.config import Config  # noqa: E402
from medianav_toolbox.models import (  # noqa: E402
    ContentItem,
    DeviceInfo,
    InstallResult,
    RegisterResult,
    ServiceEndpoints,
    SyncResult,
)

__all__ = ["Toolbox", "Config"]


class Toolbox:
    """Main entry point for the medianav_toolbox library.

    Usage:
        tb = Toolbox(usb_path="/media/usb")  # credentials from .env
        tb.boot()
        tb.login()
        device = tb.detect_device()
        catalog = tb.catalog()
        files = tb.download(catalog)
        tb.install(files)
    """

    def __init__(
        self,
        usb_path: str | None = None,
        username: str | None = None,
        password: str | None = None,
        config: Config | None = None,
    ):
        import os
        from pathlib import Path

        self.config = config or Config.from_env()
        self.usb_path = Path(usb_path or os.environ.get("NAVIEXTRAS_USB_PATH", "."))
        self._username = username
        self._password = password
        self._client = None
        self._endpoints = None
        self._session = None
        self._device = None
        self._market = None

    def _get_client(self):
        if self._client is None:
            from medianav_toolbox.api.client import NaviExtrasClient

            self._client = NaviExtrasClient(self.config)
        return self._client

    def boot(self) -> ServiceEndpoints:
        """Discover API service endpoints."""
        from medianav_toolbox.api.boot import boot

        self._endpoints = boot(self._get_client())
        return self._endpoints

    def login(self):
        """Authenticate with NaviExtras server."""
        from medianav_toolbox.api.market import MarketAPI
        from medianav_toolbox.auth import load_credentials

        if not self._endpoints:
            self.boot()
        creds = load_credentials(self._username, self._password)
        device = self._device or self.detect_device()
        self._market = MarketAPI(self._get_client(), self._endpoints)
        self._session = self._market.login(creds, device)
        return self._session

    def detect_device(self) -> DeviceInfo:
        """Read device identity from USB drive."""
        from medianav_toolbox.device import detect_drive

        device = detect_drive(self.usb_path)
        if device is None:
            raise FileNotFoundError(f"No valid MediaNav drive at {self.usb_path}")
        self._device = device
        return device

    def register(self) -> RegisterResult:
        """Register device with server."""
        from medianav_toolbox.api.register import get_device_model_list, register_device

        if not self._endpoints:
            self.boot()
        device = self._device or self.detect_device()
        get_device_model_list(self._get_client(), self._endpoints)
        return register_device(self._get_client(), self._endpoints, device)

    def catalog(self) -> list[ContentItem]:
        """Get available content catalog."""
        from medianav_toolbox.api.catalog import get_installed_catalog

        return get_installed_catalog(self.usb_path)

    def download(self, items: list[ContentItem] | None = None, progress_cb=None) -> list:
        """Download content items."""
        from medianav_toolbox.download import DownloadManager

        dm = DownloadManager(self.config, self._get_client())
        # TODO: convert ContentItems to DownloadItems when market API returns URLs
        return []

    def install(self, files: list, progress_cb=None) -> InstallResult:
        """Install downloaded files to USB."""
        from medianav_toolbox.installer import ContentInstaller

        inst = ContentInstaller(self.usb_path)
        return inst.install([], files, progress_cb)

    def sync(self, progress_cb=None) -> SyncResult:
        """Full pipeline: detect → boot → login → catalog → download → install."""
        device = self.detect_device()
        self.boot()
        self.login()
        catalog = self.catalog()
        files = self.download(catalog, progress_cb)
        result = self.install(files, progress_cb)
        return SyncResult(
            success=result.success,
            installed_count=result.installed_count,
            errors=result.errors,
        )

    def close(self):
        if self._client:
            self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
