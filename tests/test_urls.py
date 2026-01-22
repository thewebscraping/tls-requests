from __future__ import annotations

from urllib.parse import unquote

import pytest
from pytest_httpserver import HTTPServer

import tls_requests
from tls_requests.models.urls import URL, Proxy, ProxyError, URLError, URLParams, URLParamsError


def request_hook(_request, response):
    response.headers["x-path"] = _request.full_path
    return response


def test_request_params(httpserver: HTTPServer):
    params = {"a": "1", "b": "2"}
    httpserver.expect_request("/params").with_post_hook(request_hook).respond_with_data(b"OK")
    response = tls_requests.get(httpserver.url_for("/params"), params=params)
    assert response.status_code == 200
    assert unquote(str(response.url)).endswith(unquote(response.headers["x-path"]))


def test_request_multi_params(httpserver: HTTPServer):
    params = {"a": ["1", "2", "3"]}
    httpserver.expect_request("/params").with_post_hook(request_hook).respond_with_data(b"OK")
    response = tls_requests.get(httpserver.url_for("/params"), params=params)
    assert response.status_code == 200
    assert unquote(str(response.url)).endswith(unquote(response.headers["x-path"]))


def test_url_basic_parsing():
    url = URL("https://example.com:8080/path?q=1#fragment")
    assert url.scheme == "https"
    assert url.host == "example.com"
    assert url.port == "8080"
    assert url.path == "/path"
    assert url.fragment == "fragment"
    assert url.query == "q=1"
    assert str(url) == "https://example.com:8080/path?q=1#fragment"


def test_url_ipv6():
    # Simple IPv6
    url1 = URL("http://[::1]/")
    assert url1.host == "::1"
    assert str(url1) == "http://[::1]/"

    # IPv6 with port and path
    url2 = URL("https://[2001:db8::1]:443/api/v1")
    assert url2.host == "2001:db8::1"
    assert url2.port == "443"
    assert str(url2) == "https://[2001:db8::1]:443/api/v1"


def test_url_idna():
    # Test with internationalized domain name
    url = URL("https://tú-phạm.com/")
    assert url.host == "xn--t-phm-7ua4524c.com"
    assert "xn--t-phm-7ua4524c.com" in str(url)


def test_url_auth():
    url = URL("http://user:pass@example.com/")
    assert url.username == "user"
    assert url.password == "pass"
    assert "user:pass@example.com" in str(url)
    # Check secure representation
    assert "[secure]" in repr(url)
    assert "pass" not in repr(url)


def test_proxy_specifics():
    # Proxy should strip path, query, and fragment
    proxy = Proxy("http://user:pass@127.0.0.1:8080/path?query=1#hash")
    assert proxy.host == "127.0.0.1"
    assert proxy.path == ""
    assert proxy.query == ""
    assert str(proxy) == "http://user:pass@127.0.0.1:8080"

    # Test allowed schemes
    with pytest.raises(tls_requests.exceptions.ProxyError):
        Proxy("ftp://127.0.0.1")

    # Test weight and metrics
    proxy.mark_failed()
    assert proxy.failures == 1
    assert proxy.weight < 1.0

    proxy.mark_success()
    assert proxy.failures == 0


def test_url_params_extra():
    p = URLParams({"a": 1})
    # copy
    p2 = p.copy()
    assert p2["a"] == "1"

    # hash
    assert hash(p) == hash(str(p))

    # eq
    assert p == {"a": "1"}
    assert p == URLParams({"a": "1"})
    assert p != {"a": "2"}
    assert p != 123

    # keys/values/items
    assert list(p.keys()) == ["a"]
    assert list(p.values()) == ["1"]
    assert list(p.items()) == [("a", "1")]


def test_url_params_normalize_types():
    p = URLParams()
    assert p.normalize(True) == "true"
    assert p.normalize(False) == "false"
    assert p.normalize(b"bytes") == "bytes"
    assert p.normalize(1.5) == "1.5"

    with pytest.raises(URLParamsError):
        p.normalize(None)

    # To hit invalid key type check in _prepare without triggering Python kwarg error
    # we pass it in the params dict instead of kwargs
    with pytest.raises(URLParamsError) as exc:
        p._prepare({123: "val"})
    assert "key type" in str(exc.value)


def test_url_netloc_ipv6():
    u = URL("http://[::1]:8080")
    assert u.host == "::1"
    assert u.netloc == "[::1]:8080"

    # Host with colon but not bracketed
    # Set port to empty to verify host-only netloc
    u.port = ""
    u.host = "my:host"
    assert u.netloc == "[my:host]"


def test_url_query_combinations():
    u = URL("http://ex.com/p?q=1")
    u.params.update({"a": "2"})
    # quote(parsed.query) + params.params
    assert u.query == "q%3D1&a=2"

    u2 = URL("http://ex.com/p")
    u2.params.update({"a": "2"})
    assert u2.query == "a=2"


def test_url_prepare_errors():
    with pytest.raises(URLError) as exc:
        u = URL(b"http://ex.com")
        assert u.host == "ex.com"

        URL(123)
    assert "Invalid URL" in str(exc.value)

    with pytest.raises(URLError) as exc:
        URL("http://invalid_idna_ÿ.com")
    assert "Invalid IDNA" in str(exc.value)

    with pytest.raises(URLError) as exc:
        URL("http://ex.com:70000")
    assert "port range" in str(exc.value)


def test_proxy_extra():
    p = Proxy("127.0.0.1:8080", weight=None)
    assert p.weight == 1.0
    assert "Proxy" in repr(p)

    with pytest.raises(ProxyError):
        p.weight = "not a number"

    # Prepare from bytes
    p2 = Proxy(b"socks5://localhost:9050")
    assert p2.scheme == "socks5"

    # Prepare without scheme
    p3 = Proxy("localhost:1080")
    assert p3.scheme == "http"

    # Prepare with invalid scheme
    with pytest.raises(ProxyError):
        Proxy("ftp://localhost")


def test_proxy_from_methods():
    # from_dict errors
    with pytest.raises(ProxyError):
        Proxy.from_dict({})

    # from_string variations
    p1 = Proxy.from_string("host:8080|2.0|us")
    assert p1.weight == 2.0
    assert p1.region == "us"

    p2 = Proxy.from_string("  user:pass@host:8080  ")
    assert p2.host == "host"

    with pytest.raises(ProxyError):
        Proxy.from_string("")


def test_url_build_secure():
    u = URL("http://user:pass@example.com")
    assert "pass" in u._build(secure=False)
    assert "[secure]" in u._build(secure=True)
