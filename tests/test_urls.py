from urllib.parse import unquote

import pytest
from pytest_httpserver import HTTPServer

import tls_requests
from tls_requests.models.urls import URL, Proxy


def request_hook(_request, response):
    response.headers['x-path'] = _request.full_path
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
