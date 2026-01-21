from __future__ import annotations

from pytest_httpserver import HTTPServer

import tls_requests


def test_missing_host_redirects(httpserver: HTTPServer):
    httpserver.expect_request("/redirects/3").respond_with_data(b"OK", status=302, headers={"Location": "/redirects/1"})
    httpserver.expect_request("/redirects/1").respond_with_data(b"OK", status=302, headers={"Location": "/redirects/2"})
    httpserver.expect_request("/redirects/2").respond_with_data(
        b"OK", status=302, headers={"Location": "/redirects/ok"}
    )
    httpserver.expect_request("/redirects/ok").respond_with_data(b"OK")
    response = tls_requests.get(httpserver.url_for("/redirects/3"))
    assert response.status_code == 200
    assert response.history[0].status_code == 302
    assert len(response.history) == 3


def test_full_path_redirects(httpserver: HTTPServer):
    httpserver.expect_request("/redirects/3").respond_with_data(
        b"OK", status=302, headers={"Location": httpserver.url_for("/redirects/1")}
    )
    httpserver.expect_request("/redirects/1").respond_with_data(
        b"OK", status=302, headers={"Location": httpserver.url_for("/redirects/2")}
    )
    httpserver.expect_request("/redirects/2").respond_with_data(
        b"OK", status=302, headers={"Location": httpserver.url_for("/redirects/ok")}
    )
    httpserver.expect_request("/redirects/ok").respond_with_data(b"OK")
    response = tls_requests.get(httpserver.url_for("/redirects/3"))
    assert response.status_code == 200
    assert response.history[0].status_code == 302
    assert len(response.history) == 3


def test_fragment_redirects(httpserver: HTTPServer):
    httpserver.expect_request("/redirects/3").respond_with_data(
        b"OK", status=302, headers={"Location": httpserver.url_for("/redirects/ok#fragment")}
    )
    httpserver.expect_request("/redirects/ok").respond_with_data(b"OK")
    response = tls_requests.get(httpserver.url_for("/redirects/3"))
    assert response.status_code == 200
    assert response.history[0].status_code == 302
    assert len(response.history) == 1
    assert response.request.url.fragment == "fragment"


def test_too_many_redirects(httpserver: HTTPServer):
    httpserver.expect_request("/redirects/3").respond_with_data(b"OK", status=302, headers={"Location": "/redirects/1"})
    httpserver.expect_request("/redirects/1").respond_with_data(b"OK", status=302, headers={"Location": "/redirects/2"})
    httpserver.expect_request("/redirects/2").respond_with_data(b"OK", status=302, headers={"Location": "/redirects/3"})
    httpserver.expect_request("/redirects/ok").respond_with_data(b"OK")
    try:
        _ = tls_requests.get(httpserver.url_for("/redirects/3"))
    except Exception as e:
        assert isinstance(e, tls_requests.exceptions.TooManyRedirects)
