"""HTTP client with retry, cookies, and user-agent for NaviExtras API.

Ref: toolbox.md §4 (HTTP communication), §17 (request flow)
"""

import time

import httpx

from medianav_toolbox.config import Config


class NaviExtrasClient:
    """HTTP client for NaviExtras API with retry and session management."""

    def __init__(self, config: Config | None = None):
        self.config = config or Config()
        self._client = httpx.Client(
            timeout=self.config.http_timeout,
            follow_redirects=True,
            headers={"User-Agent": self.config.user_agent},
        )

    def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        """Send HTTP request with retry on failure."""
        last_exc = None
        for attempt in range(self.config.max_retries):
            try:
                resp = self._client.request(method, url, **kwargs)
                if resp.status_code >= 500 and attempt < self.config.max_retries - 1:
                    time.sleep(2**attempt)
                    continue
                return resp
            except (httpx.TimeoutException, httpx.ConnectError, httpx.RemoteProtocolError) as e:
                last_exc = e
                if attempt < self.config.max_retries - 1:
                    time.sleep(2**attempt)
        raise last_exc  # type: ignore[misc]

    def get(self, url: str, **kwargs) -> httpx.Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> httpx.Response:
        return self.request("POST", url, **kwargs)

    @property
    def cookies(self) -> httpx.Cookies:
        return self._client.cookies

    def close(self):
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
