from pytest_httpserver import HTTPServer
from werkzeug import Request, Response

import tls_requests
from tls_requests.models.tls import TLSConfig


def hook_request_headers(_request: Request, response: Response) -> Response:
    response.headers = _request.headers
    return response


def hook_response_headers(_request: Request, response: Response) -> Response:
    response.headers["foo"] = "bar"
    return response


def hook_response_case_insensitive_headers(_request: Request, response: Response) -> Response:
    response.headers["Foo"] = "bar"
    return response


def test_request_headers(httpserver: HTTPServer):
    httpserver.expect_request("/headers").with_post_hook(hook_request_headers).respond_with_data(b"OK")
    response = tls_requests.get(httpserver.url_for("/headers"), headers={"foo": "bar"})
    assert response.status_code == 200
    assert response.request.headers["foo"] == "bar"


def test_response_headers(httpserver: HTTPServer):
    httpserver.expect_request("/headers").with_post_hook(hook_response_headers).respond_with_data(b"OK")
    response = tls_requests.get(httpserver.url_for("/headers"))
    assert response.status_code, 200
    assert response.headers["foo"] == "bar"


def test_response_case_insensitive_headers(httpserver: HTTPServer):
    httpserver.expect_request("/headers").with_post_hook(hook_response_case_insensitive_headers).respond_with_data(b"OK")
    response = tls_requests.get(httpserver.url_for("/headers"))
    assert response.status_code, 200
    assert response.headers["foo"] == "bar"


def test_chrome_dynamic_headers():
    # Test chrome_112
    config = TLSConfig.from_kwargs(tls_identifier="chrome_112")
    headers = config.headers
    assert "Chrome/112" in headers.get("user-agent", "")
    assert 'v="112"' in headers.get("sec-ch-ua", "")

    # Test chrome_133 (default)
    config_default = TLSConfig.from_kwargs(tls_identifier="chrome_133")
    headers_default = config_default.headers
    assert "Chrome/133" in headers_default.get("user-agent", "")
    assert 'v="133"' in headers_default.get("sec-ch-ua", "")


def test_firefox_dynamic_headers():
    # Test firefox_120
    config = TLSConfig.from_kwargs(tls_identifier="firefox_120")
    headers = config.headers
    assert "Firefox/120" in headers.get("user-agent", "")
    assert "rv:120" in headers.get("user-agent", "")


def test_safari_dynamic_headers():
    # Test safari_17
    config = TLSConfig.from_kwargs(tls_identifier="safari_17")
    headers = config.headers
    assert "Version/17" in headers.get("user-agent", "")


def test_custom_headers_override():
    # Custom headers should not be overridden by dynamic injection
    custom_headers = {"User-Agent": "MyCustomUA", "X-Test": "Value"}
    config = TLSConfig.from_kwargs(tls_identifier="chrome_112", headers=custom_headers)
    assert config.headers["User-Agent"] == "MyCustomUA"
    assert config.headers["X-Test"] == "Value"
    assert "sec-ch-ua" not in config.headers  # Should not inject if headers provided


def test_no_injection_for_non_browser():
    # Injection should only happen for chrome/firefox/safari
    config = TLSConfig.from_kwargs(tls_identifier="okhttp4_android_12")
    assert not config.headers  # Should be empty or only basic defaults if any
