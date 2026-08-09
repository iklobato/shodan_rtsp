"""Runnable self-checks for the refactored logic. No test framework needed:

python3 -m tests.test_refactor
"""

from models.managers import CameraRepository
from scanners.config import CheckersConfig
from scanners.rtsp_probe import RtspTarget
from wordlists.proxy_downloader import Proxy, ProxyDownloader


def test_rtsp_target_url_is_formatted_once():
    target = RtspTarget(
        host="10.0.0.1",
        port=554,
        user="admin",
        password="pass",
        url_template="rtsp://{}:{}@{}:{}/live",
    )
    assert target.url == "rtsp://admin:pass@10.0.0.1:554/live", target.url


def test_sanitize_city_strips_injection_chars():
    assert CameraRepository._sanitize_city('Sa\'o; "Paulo"') == "Sao Paulo"
    assert CameraRepository._sanitize_city(None) == ""


def test_proxy_parse_coerces_port_and_rejects_junk():
    assert Proxy.parse("1.2.3.4:80") == Proxy(ip="1.2.3.4", port=80)
    assert Proxy.parse("3.3.3.3:notaport") is None
    assert Proxy.parse("broken-line") is None


def test_proxy_downloader_loads_all_valid_lines(patch_text):
    pd = ProxyDownloader("http://example/config.json")
    patch_text("1.1.1.1:8080\n2.2.2.2:3128\nbroken-line\n3.3.3.3:notaport\n")
    pd.load_proxies("http://example/list.txt")
    assert pd._proxies == [
        Proxy(ip="1.1.1.1", port=8080),
        Proxy(ip="2.2.2.2", port=3128),
    ], pd._proxies


def test_proxies_property_respects_limit():
    pd = ProxyDownloader("http://example/config.json", limit=2)
    pd._proxies = [Proxy(ip=f"9.9.9.{i}", port=80) for i in range(5)]
    assert len(pd.proxies) == 2


def test_checkers_randomize_is_coerced_to_bool():
    # FilePath only checks existence, so point it at a file we know exists.
    existing = "config.ini"
    assert (
        CheckersConfig(
            wordlist_users=existing,
            wordlist_passwords=existing,
            wordlist_rtsp_urls=existing,
            randomize="false",
        ).randomize
        is False
    )
    assert (
        CheckersConfig(
            wordlist_users=existing,
            wordlist_passwords=existing,
            wordlist_rtsp_urls=existing,
            randomize="true",
        ).randomize
        is True
    )


class _FakeResponse:
    def __init__(self, text):
        self.status_code = 200
        self.text = text


def _make_text_patcher():
    def patch(text):
        import wordlists.proxy_downloader as mod

        mod.requests.get = lambda url: _FakeResponse(text)  # noqa: ARG005

    return patch


def _run():
    patch_text = _make_text_patcher()
    test_rtsp_target_url_is_formatted_once()
    test_sanitize_city_strips_injection_chars()
    test_proxy_parse_coerces_port_and_rejects_junk()
    test_proxy_downloader_loads_all_valid_lines(patch_text)
    test_proxies_property_respects_limit()
    test_checkers_randomize_is_coerced_to_bool()

    try:
        from scanners.task import ShodanBanner
    except ImportError:
        print("OK (ShodanBanner check skipped: nmap/shodan not installed)")
    else:
        banner = ShodanBanner(
            ip_str="1.2.3.4",
            port="554",
            location={"city": "SP", "unrelated": 1},
            junk="ignored",
        )
        assert banner.port == 554
        assert banner.location.city == "SP"

    print("all self-checks passed")


if __name__ == "__main__":
    _run()
