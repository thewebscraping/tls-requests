from __future__ import annotations

import datetime

import pytest

from tls_requests.exceptions import Base64DecodeError, HTTPError
from tls_requests.models.request import Request
from tls_requests.models.response import Response
from tls_requests.models.tls import TLSResponse


def test_response_elapsed_setter():
    r = Response(200)
    delta = datetime.timedelta(seconds=1)
    r.elapsed = delta
    assert r.elapsed == delta
    assert r.elapsed.total_seconds() == 1


def test_response_request_error():
    r = Response(200)
    with pytest.raises(RuntimeError):
        _ = r.request


def test_response_next_setter():
    r = Response(200)
    req = Request("GET", "http://ex.com")
    r.next = req
    assert r.next is req


def test_response_cookies_backfill():
    req = Request("GET", "http://example.com")
    # Response with cookie metadata but no domain
    r = Response(200, cookies={"session": "123"}, request=req)
    # The domain should be backfilled from request.url.host
    c = list(r.cookies.cookiejar)[0]
    assert c.domain == "example.com"


def test_response_charset_missing():
    r = Response(200, headers={"Content-Type": "application/json"})
    assert r.charset is None  # No charset param in content-type

    r2 = Response(200)
    assert r2.charset is None


def test_response_encoding_variations():
    r = Response(200, headers={"Content-Type": "text/html; charset=gbk,utf-8"})
    # it should take the first one
    assert r.encoding == "gbk"

    r2 = Response(200, body=b"hello")
    # Should fallback to utf-8 if no charset detected
    assert r2.encoding == "utf-8"

    # Test callable encoding
    def my_encoding(resp):
        return "ascii"

    r3 = Response(200, default_encoding=my_encoding)
    assert r3.encoding == "ascii"


def test_response_ok_and_bool():
    req = Request("GET", "http://ex.com")
    r_ok = Response(200, request=req)
    assert r_ok.ok is True
    assert bool(r_ok) is True

    r_fail = Response(404, request=req)
    assert r_fail.ok is False
    assert bool(r_fail) is False


def test_response_is_permanent_redirect():
    r1 = Response(301, headers={"Location": "/new"})
    assert r1.is_permanent_redirect is True
    r2 = Response(308, headers={"Location": "/new"})
    assert r2.is_permanent_redirect is True
    r3 = Response(302, headers={"Location": "/new"})
    assert r3.is_permanent_redirect is False


def test_response_raise_for_status_messages():
    # Code < 100
    r1 = Response(50, body=b"TLS Error", request=Request("GET", "http://ex.com"))
    with pytest.raises(HTTPError) as exc:
        r1.raise_for_status()
    assert "TLS Client Error" in str(exc.value)

    # 500 error
    r2 = Response(500, request=Request("GET", "http://ex.com"))
    with pytest.raises(HTTPError) as exc:
        r2.raise_for_status()
    assert "Server Error" in str(exc.value)


def test_response_json():
    r = Response(200, body=b'{"key": "value"}')
    r.read()  # Must read to populate content/text
    assert r.json() == {"key": "value"}


def test_response_read_none_stream():
    r = Response(200)
    r.stream = None
    assert r.read() == b""


def test_response_from_tls_response_b64_error():
    tr = TLSResponse(status=200, body="not_base64_and_has_comma,invalid", id="123")
    with pytest.raises(Base64DecodeError):
        Response.from_tls_response(tr, is_byte_response=True)


def test_response_repr():
    r = Response(200)
    assert repr(r) == "<Response [200]>"
