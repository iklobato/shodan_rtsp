"""Runnable self-checks for the refactored logic. No test framework needed:

python3 -m tests.test_refactor
"""

from models.managers import CameraRepository
from scanners.config import CheckersConfig
from scanners.proxy import TwoCaptchaProxy, TwoCaptchaSettings
from scanners.rtsp_probe import RtspTarget


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


def test_checkers_randomize_is_coerced_to_bool():
    existing = "config.ini"  # FilePath only checks existence
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


def _proxy(auth_mode, **overrides):
    settings = TwoCaptchaSettings(
        proxy_2captcha_aip_token="tok", auth_mode=auth_mode, **overrides
    )
    return TwoCaptchaProxy(settings=settings)


def test_first_connection_reads_confirmed_success_shape():
    # Confirmed live: data is a list of full proxy URLs.
    proxy = _proxy("whitelist", protocol="http")
    reply = {
        "status": "OK",
        "data": ["http://78.141.222.54:15000", "http://78.141.222.54:15001"],
    }
    conn = proxy._first_connection(reply)
    assert conn == "http://78.141.222.54:15000"
    assert proxy._normalize(conn) == "http://78.141.222.54:15000"


def test_first_connection_prepends_scheme_for_bare_ip_port():
    proxy = _proxy("whitelist", protocol="socks5")
    conn = proxy._first_connection({"status": "OK", "data": ["1.2.3.4:8080"]})
    assert proxy._normalize(conn) == "socks5://1.2.3.4:8080"


def test_first_connection_rejects_error_packed_in_200():
    # The real failure seen when country was missing (FK error inside data).
    proxy = _proxy("whitelist")
    reply = {
        "status": "OK",
        "data": ["Foreign key constraint failed on country_code", "Bad Request", 400],
    }
    try:
        proxy._first_connection(reply)
    except RuntimeError as e:
        assert "no usable proxy" in str(e)
    else:
        raise AssertionError("expected RuntimeError when data holds an error")


def test_first_connection_raises_on_error_status():
    proxy = _proxy("whitelist")
    try:
        proxy._first_connection(
            {"status": "ERROR_MISSING_IP", "message": "IP address is missing"}
        )
    except RuntimeError as e:
        assert "IP address is missing" in str(e)
    else:
        raise AssertionError("expected RuntimeError on error status")


def test_login_url_needs_gateway_fields():
    proxy = _proxy(
        "login", gateway_host="gw.example", gateway_port=8000, gateway_password="pw"
    )
    assert proxy._build_login_url("uc123") == "http://uc123:pw@gw.example:8000"

    incomplete = _proxy("login")
    try:
        incomplete._build_login_url("uc123")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError when gateway fields are missing")


def _run():
    test_rtsp_target_url_is_formatted_once()
    test_sanitize_city_strips_injection_chars()
    test_checkers_randomize_is_coerced_to_bool()
    test_first_connection_reads_confirmed_success_shape()
    test_first_connection_prepends_scheme_for_bare_ip_port()
    test_first_connection_rejects_error_packed_in_200()
    test_first_connection_raises_on_error_status()
    test_login_url_needs_gateway_fields()

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
