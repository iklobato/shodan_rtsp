import logging
import random

import requests
from pydantic import BaseModel, ValidationError


class Proxy(BaseModel):
    ip: str
    port: int

    @classmethod
    def parse(cls, line: str):
        line = line.strip()
        if ":" not in line:
            return None
        ip, port = line.split(":", 1)
        try:
            return cls(ip=ip, port=port)
        except ValidationError:
            return None


class ProxyDownloader:

    def __init__(self, proxy_file_path: str = None, limit: int = 100):
        self.proxy_file_path = proxy_file_path
        self._limit = limit
        self._proxies = []

    @property
    def proxy(self):
        return self.get_random_proxy()

    @property
    def proxies(self):
        self._ensure_loaded()
        return self._proxies[: self._limit]

    def _ensure_loaded(self):
        if not self._proxies:
            self.load_default_proxies()

    def load_default_proxies(self):
        response = requests.get(self.proxy_file_path)
        if response.status_code != 200:
            logging.error(f"Failed to download proxies from {self.proxy_file_path}")
            return
        for provider in response.json()["proxy-providers"]:
            if provider["type"] != 1:
                continue
            self.load_proxies(provider["url"])
            break

    def load_proxies(self, url):
        response = requests.get(url)
        if response.status_code != 200:
            logging.error(f"Failed to download proxies from {url}")
            return
        for line in response.text.splitlines():
            proxy = Proxy.parse(line)
            if proxy is not None:
                self._proxies.append(proxy)

    def get_random_proxy(self):
        self._ensure_loaded()
        if not self._proxies:
            return None
        return random.choice(self._proxies)


if __name__ == "__main__":
    pd = ProxyDownloader(
        "https://raw.githubusercontent.com/MatrixTM/MHDDoS/main/config.json"
    )
    print(pd.proxy)
