from __future__ import annotations

import pytest
from pytest_httpserver import HTTPServer
from werkzeug import Request, Response

import tls_requests
from tls_requests.models.headers import HeaderAlias, HeaderError, Headers
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
    httpserver.expect_request("/headers").with_post_hook(hook_response_case_insensitive_headers).respond_with_data(
        b"OK"
    )
    response = tls_requests.get(httpserver.url_for("/headers"))
    assert response.status_code, 200
    assert response.headers["foo"] == "bar"


def test_chrome_dynamic_headers():
    # Test chrome_112
    config = TLSConfig.from_kwargs(client_identifier="chrome_112")
    headers = config.headers
    assert "Chrome/112" in headers.get("user-agent", "")
    assert 'v="112"' in headers.get("sec-ch-ua", "")

    # Test chrome_133 (default)
    config_default = TLSConfig.from_kwargs(client_identifier="chrome_133")
    headers_default = config_default.headers
    assert "Chrome/133" in headers_default.get("user-agent", "")
    assert 'v="133"' in headers_default.get("sec-ch-ua", "")


def test_firefox_dynamic_headers():
    # Test firefox_120
    config = TLSConfig.from_kwargs(client_identifier="firefox_120")
    headers = config.headers
    assert "Firefox/120" in headers.get("user-agent", "")
    assert "rv:120" in headers.get("user-agent", "")


def test_safari_dynamic_headers():
    # Test safari_17
    config = TLSConfig.from_kwargs(client_identifier="safari_17")
    headers = config.headers
    assert "Version/17" in headers.get("user-agent", "")


def test_custom_headers_override():
    # Custom headers should not be overridden by dynamic injection
    custom_headers = {"User-Agent": "MyCustomUA", "X-Test": "Value"}
    config = TLSConfig.from_kwargs(client_identifier="chrome_112", headers=custom_headers)
    assert config.headers["User-Agent"] == "MyCustomUA"
    assert config.headers["X-Test"] == "Value"
    assert "sec-ch-ua" not in config.headers  # Should not inject if headers provided


def test_no_injection_for_non_browser():
    # Injection should only happen for chrome/firefox/safari
    config = TLSConfig.from_kwargs(client_identifier="okhttp4_android_12")
    assert not config.headers  # Should be empty or only basic defaults if any


def test_header_alias_contains():
    assert HeaderAlias.contains("lower") is True
    assert HeaderAlias.contains("capitalize") is True
    assert HeaderAlias.contains("*") is True
    assert HeaderAlias.contains("invalid") is False


def test_headers_init_alias():
    h = Headers(alias="*")
    assert h.alias == "*"
    h2 = Headers(alias="invalid")
    assert h2.alias == "lower"


def test_headers_keys_values():
    h = Headers({"A": "1", "B": "2"})
    assert list(h.keys()) == ["a", "b"]
    assert list(h.values()) == ["1", "2"]


def test_headers_update_none():
    h = Headers({"A": "1"})
    h.update(None)
    assert h["a"] == "1"


def test_headers_prepare_from_headers_instance():
    h1 = Headers({"A": "1"})
    h2 = Headers(h1)
    assert h2["a"] == "1"


def test_headers_prepare_invalid_format():
    with pytest.raises(HeaderError):
        Headers(123)

    # Test valid but weird formats
    h = Headers([("A", "1", "extra ignored")])
    assert h["a"] == "1"

    with pytest.raises(HeaderError):
        Headers([(1,)])  # too few items


def test_headers_normalize_key_all():
    h = Headers({"User-Agent": "test"}, alias="*")
    assert "User-Agent" in h
    assert "user-agent" not in h


def test_headers_normalize_value_errors():
    h = Headers()
    with pytest.raises(HeaderError) as exc:
        h["A"] = {"invalid": "dict"}
    assert "cannot be a dictionary" in str(exc.value)

    with pytest.raises(HeaderError) as exc:
        h["A"] = [{"dict": "inside list"}]
    assert "items cannot be a dictionary" in str(exc.value)


def test_headers_setitem_overwrite():
    h = Headers({"A": "1"})
    h["a"] = "2"
    assert h["a"] == "2"
    assert len(h) == 1


def test_headers_delitem_missing():
    h = Headers({"A": "1"})
    del h["B"]  # should not raise error
    assert len(h) == 1


def test_headers_eq_variations():
    h1 = Headers({"A": "1"})
    assert h1 == {"a": "1"}
    assert h1 == [("a", "1")]
    assert h1 != 123
    assert h1 != {"a": "2"}

    # Mock HeaderError in eq
    class BadHeaders:
        def items(self):
            raise ValueError("bad")

    assert h1 != BadHeaders()


def test_headers_repr_secure():
    h = Headers({"Authorization": "Bearer secret", "X-Normal": "val"})
    r = repr(h)
    assert "[secure]" in r
    assert "secret" not in r
    assert "val" in r


def test_headers_normalize_value_list():
    h = Headers({"A": ["1", "2"]})
    assert h["a"] == "1,2"
    h["b"] = ("3", "4")
    assert h["b"] == "3,4"
