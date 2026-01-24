from __future__ import annotations

import tls_requests


def test_http_proxy():
    proxy = tls_requests.Proxy("http://localhost:8080")
    assert proxy.scheme == "http"
    assert proxy.host == "localhost"
    assert proxy.port == "8080"
    assert proxy.url == "http://localhost:8080"


def test_https_proxy():
    proxy = tls_requests.Proxy("https://localhost:8080")
    assert proxy.scheme == "https"
    assert proxy.host == "localhost"
    assert proxy.port == "8080"
    assert proxy.url == "https://localhost:8080"


def test_socks5_proxy():
    proxy = tls_requests.Proxy("socks5://localhost:8080")
    assert proxy.scheme == "socks5"
    assert proxy.host == "localhost"
    assert proxy.port == "8080"
    assert proxy.url == "socks5://localhost:8080"


def test_proxy_with_params():
    proxy = tls_requests.Proxy("http://localhost:8080?a=b", params={"foo": "bar"})
    assert proxy.scheme == "http"
    assert proxy.host == "localhost"
    assert proxy.port == "8080"
    assert proxy.url == "http://localhost:8080"


def test_auth_proxy():
    proxy = tls_requests.Proxy("http://username:password@localhost:8080")
    assert proxy.scheme == "http"
    assert proxy.host == "localhost"
    assert proxy.port == "8080"
    assert proxy.auth == ("username", "password")
    assert proxy.url == "http://username:password@localhost:8080"


def test_unsupported_proxy_scheme():
    try:
        _ = tls_requests.Proxy("unknown://localhost:8080")
    except Exception as e:
        assert isinstance(e, tls_requests.exceptions.ProxyError)


def test_ipv6_proxy():
    # IPv6 without port
    proxy = tls_requests.Proxy("http://[::1]")
    assert proxy.host == "::1"
    assert proxy.url == "http://[::1]"

    # IPv6 with port
    proxy2 = tls_requests.Proxy("http://[2001:db8::1]:8080")
    assert proxy2.host == "2001:db8::1"
    assert proxy2.port == "8080"
    assert proxy2.url == "http://[2001:db8::1]:8080"


def test_ipv6_proxy_auth():
    # IPv6 with auth and port
    proxy = tls_requests.Proxy("socks5://user:pass@[::1]:1080")
    assert proxy.scheme == "socks5"
    assert proxy.host == "::1"
    assert proxy.port == "1080"
    assert proxy.auth == ("user", "pass")
    assert proxy.url == "socks5://user:pass@[::1]:1080"


def test_ipv6_no_brackets():
    # Should handle IPv6 even if brackets are missing by default in some simple strings
    # though usually URL expects brackets for IPv6.
    # Our Proxy.from_string or URL may handle it if it detects it's an IP.
    # Actually URL._prepare uses ipaddress.ip_address(hostname)

    # Testing Proxy.from_string with IPv6
    proxy = tls_requests.Proxy.from_string("[::1]:8080|5.0|us")
    assert proxy.host == "::1"
    assert proxy.weight == 5.0
    assert proxy.region == "us"
    assert "[::1]:8080" in proxy.url
