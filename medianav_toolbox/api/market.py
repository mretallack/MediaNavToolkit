"""Market API calls — the core server interaction protocol.

Ref: toolbox.md §6 (market calls), §16 (function→path→arg mapping), §19.1 (lifecycle)

Call sequence: LOGIN → SEND_DRIVES → SEND_FINGERPRINT → SEND_MD5 →
              SEND_SGN_FILE_VALIDITY → SEND_DEVICE_STATUS → GET_PROCESS →
              [download] → SEND_PROCESS_STATUS → SEND_BACKUPS
"""

from medianav_toolbox.api.client import NaviExtrasClient
from medianav_toolbox.auth import AuthenticationError, auth_headers, extract_jsessionid
from medianav_toolbox.models import (
    Credentials,
    DeviceInfo,
    DownloadItem,
    DriveInfo,
    ProcessInfo,
    ServiceEndpoints,
    Session,
)

# Content type for all market calls (toolbox.md §18)
IGO_BINARY = "application/vnd.igo-binary; v=1"
JSON_CT = "application/json"


class MarketAPI:
    """Market API client for the NaviExtras index service.

    All market calls go to {index_url}/{path} as POST requests.
    Ref: toolbox.md §16 complete path list.
    """

    def __init__(
        self,
        client: NaviExtrasClient,
        endpoints: ServiceEndpoints,
        session: Session | None = None,
    ):
        self._client = client
        self._endpoints = endpoints
        self._session = session or Session()

    @property
    def session(self) -> Session:
        return self._session

    def _post(
        self, path: str, body: dict | bytes | None = None, auth_mode: str = "device-auth"
    ) -> dict:
        """Send a market call POST request."""
        url = f"{self._endpoints.index_v3}{path}"
        headers = auth_headers(self._session, auth_mode)

        if isinstance(body, bytes):
            headers["Content-Type"] = IGO_BINARY
            resp = self._client.post(url, content=body, headers=headers)
        else:
            headers["Content-Type"] = JSON_CT
            resp = self._client.post(url, json=body or {}, headers=headers)

        # Capture JSESSIONID from response
        jsid = extract_jsessionid(dict(resp.cookies))
        if jsid:
            self._session.jsessionid = jsid

        return {"status": resp.status_code, "body": resp.content, "headers": dict(resp.headers)}

    # --- Core market calls (toolbox.md §6.1 order) ---

    def login(self, credentials: Credentials, device: DeviceInfo) -> Session:
        """POST /login — authenticate with full-auth. Ref: line 155845, 76-byte arg."""
        result = self._post(
            "/login",
            {
                "username": credentials.username,
                "password": credentials.password,
                "device_type": self._client.config.device_type,
                "brand": self._client.config.brand,
                "appcid": device.appcid,
            },
            auth_mode="full-auth",
        )
        if result["status"] == 200:
            self._session.is_authenticated = True
            return self._session
        raise AuthenticationError(f"Login failed: HTTP {result['status']}")

    def send_drives(self, drives: list[DriveInfo]) -> dict:
        """POST /senddrives — report USB drives. Ref: line 156243, 32-byte arg."""
        payload = [
            {"path": str(d.drive_path), "free": d.free_space, "total": d.total_space}
            for d in drives
        ]
        return self._post("/senddrives", {"drives": payload})

    def send_fingerprint(self, fingerprint_hex: str) -> dict:
        """POST /sendfingerprint — send device fingerprint. Ref: line 156646, 76-byte arg."""
        return self._post("/sendfingerprint", {"fingerprint": fingerprint_hex})

    def send_md5(self, checksums: dict[str, str]) -> dict:
        """POST /sendmd5 — send file checksums. Ref: line 156779, 40-byte arg."""
        return self._post("/sendmd5", {"checksums": checksums})

    def send_sgn_file_validity(self, validity: dict) -> dict:
        """POST /sendsgnfilevalidity — validate signatures. Ref: line 157175, 36-byte arg."""
        return self._post("/sendsgnfilevalidity", validity)

    def send_device_status(self, status: dict) -> dict:
        """POST /senddevicestatus — report device status. Ref: line 156111, 240-byte arg."""
        return self._post("/senddevicestatus", status)

    def get_process(self) -> ProcessInfo:
        """POST /getprocess — get available updates. Ref: line 155713, 8-byte arg."""
        result = self._post("/getprocess", {})
        # TODO: parse igo-binary response into ProcessInfo when format is fully decoded
        return ProcessInfo(process_id=0, downloads=[], total_size=0)

    def send_process_status(self, process_id: int, status: str, progress: int = 0) -> dict:
        """POST /sendprocessstatus — report progress. Ref: line 156911, 80-byte arg."""
        return self._post(
            "/sendprocessstatus", {"process_id": process_id, "status": status, "progress": progress}
        )

    def send_backups(self, backups: list[dict]) -> dict:
        """POST /sendbackups — send backup info. Ref: line 155977, 32-byte arg."""
        return self._post("/sendbackups", {"backups": backups})

    def send_error(self, code: int, message: str) -> dict:
        """POST /senderror — report error. Ref: line 156375, 32-byte arg."""
        return self._post("/senderror", {"error_code": code, "message": message})

    def send_replacement_drives(self, drives: list[DriveInfo]) -> dict:
        """POST /sendreplacementdrives — report replacement drives. Ref: line 157043, 40-byte arg."""
        payload = [
            {"path": str(d.drive_path), "free": d.free_space, "total": d.total_space}
            for d in drives
        ]
        return self._post("/sendreplacementdrives", {"drives": payload})

    def send_file_content(self, content: bytes) -> dict:
        """POST /sendfilecontent — send file content. Ref: line 156507, 80-byte arg."""
        return self._post("/sendfilecontent", content)

    def get_settings(self) -> dict:
        """POST /settings — get/set settings. Ref: line 157319."""
        return self._post("/settings", {})
