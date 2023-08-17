import logging
import random

import requests


class ProxyDownloader:

    def __init__(self, proxy_file_path: str = None):
        self.proxy_file_path = proxy_file_path
        self._proxies = []

    @property
    def proxy(self):
        return self.get_random_proxy()

    @property
    def proxies(self, limit: int = 100):
        return self._proxies[:limit]

    def load_default_proxies(self):
        response = requests.get(self.proxy_file_path)
        if response.status_code != 200:
            logging.error(f'Failed to download proxies from {self.proxy_file_path}')
            return
        for providers in response.json()["proxy-providers"]:
            if providers['type'] != 1:
                continue
            self.load_proxies(providers['url'])
            break

    def load_proxies(self, url):
        response = requests.get(url)
        if response.status_code != 200:
            logging.error(f'Failed to download proxies from {url}')
            return
        for providers in response.text.split('\n'):
            ip, port = providers.split(':')
            self._proxies.append({
                'ip': ip,
                'port': int(port)
            })
            break

    def get_random_proxy(self):
        if not self._proxies:
            self.load_default_proxies()
        if not self._proxies:
            return None
        return random.choice(self._proxies)


if __name__ == '__main__':
    pd = ProxyDownloader('https://raw.githubusercontent.com/MatrixTM/MHDDoS/main/config.json')
    print(pd.proxy)
