"""2captcha residential proxy provider.

Whitelist mode (recommended for a scanner on a fixed box): the machine's
public IPv4 must be added to the account whitelist in the 2captcha web
dashboard first (there is no API for that step). Then the API hands back an
ip:port that connects without credentials.

Login mode: username:password@host:port, where the username is read from the
API and the host/port/password come from the dashboard (env-configured).

Run `python -m scanners.proxy` to generate and print a proxy URL.
"""

import json
import logging
import urllib.parse
import urllib.request

from pydantic_settings import BaseSettings, SettingsConfigDict

_API = "https://api.2captcha.com"
_IP_ECHO = "https://api.ipify.org"


class TwoCaptchaSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    proxy_2captcha_aip_token: str
    auth_mode: str = "whitelist"  # 'whitelist' | 'login'
    protocol: str = "http"  # http | https | socks5
    public_ip: str = ""  # whitelist mode; auto-detected when empty
    gateway_host: str = ""  # login mode (from dashboard)
    gateway_port: int = 0  # login mode (from dashboard)
    gateway_password: str = ""  # login mode (from dashboard)


class TwoCaptchaProxy:
    """Builds a proxy URL for outbound tools, self-configured from the API."""

    def __init__(
        self,
        settings: TwoCaptchaSettings = None,
        http_get_json=None,
        http_get_text=None,
    ):
        self._s = settings or TwoCaptchaSettings()
        self._get_json = http_get_json or self._default_get_json
        self._get_text = http_get_text or self._default_get_text
        self._cached_url = None

    def url(self) -> str:
        if self._cached_url is None:
            self._cached_url = self._resolve_url()
        return self._cached_url

    def requests_proxies(self) -> dict:
        proxy_url = self.url()
        return {"http": proxy_url, "https": proxy_url}

    def _resolve_url(self) -> str:
        if self._s.auth_mode == "login":
            return self._build_login_url(self._account_username())
        ip = self._s.public_ip or self._get_text(_IP_ECHO).strip()
        data = self._api(
            "/proxy/generate_white_list_connections",
            ip=ip,
            protocol=self._s.protocol,
            connection_count=1,
        )
        return self._build_whitelist_url(self._first_connection(data))

    def _build_login_url(self, username: str) -> str:
        s = self._s
        if not (s.gateway_host and s.gateway_port and s.gateway_password):
            raise ValueError(
                "login mode needs gateway_host, gateway_port and gateway_password"
            )
        return f"{s.protocol}://{username}:{s.gateway_password}@{s.gateway_host}:{s.gateway_port}"

    def _build_whitelist_url(self, connection: str) -> str:
        return f"{self._s.protocol}://{connection}"

    def _account_username(self) -> str:
        data = self._api("/proxy")
        return data["data"]["username"]

    @staticmethod
    def _first_connection(data: dict) -> str:
        """Pull the first ip:port out of a generate_white_list_connections reply.

        ponytail: response shape confirmed only for the error path so far; the
        success shape is handled defensively and the raw body is raised on a
        miss so the real structure surfaces on first live run instead of a
        silent wrong proxy.
        """
        if data.get("status") != "OK":
            raise RuntimeError(f'2captcha proxy error: {data.get("message", data)}')
        payload = data.get("data", data)
        candidates = (
            payload
            if isinstance(payload, list)
            else (payload.get("connections") or payload.get("list") or [])
        )
        for item in candidates:
            if isinstance(item, str) and ":" in item:
                return item
            if isinstance(item, dict):
                ip, port = item.get("ip"), item.get("port")
                if ip and port:
                    return f"{ip}:{port}"
        raise RuntimeError(f"no connection found in 2captcha reply: {data}")

    def _api(self, path: str, **params) -> dict:
        params["key"] = self._s.proxy_2captcha_aip_token
        return self._get_json(f"{_API}{path}?{urllib.parse.urlencode(params)}")

    @staticmethod
    def _default_get_json(url: str) -> dict:
        with urllib.request.urlopen(url, timeout=25) as response:
            return json.loads(response.read().decode())

    @staticmethod
    def _default_get_text(url: str) -> str:
        with urllib.request.urlopen(url, timeout=15) as response:
            return response.read().decode()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    proxy = TwoCaptchaProxy()
    logging.info("Generated proxy: %s", proxy.url())
