from __future__ import annotations

import time

from pytest_httpserver import HTTPServer

import tls_requests


def log_request_return(request):
    request.headers["X-Hook"] = "123456"
    return request


def log_request_no_return(request):
    request.headers["X-Hook"] = "123456"


def log_response_raise_on_4xx_5xx(response):
    response.raise_for_status()


def test_request_hook(httpserver: HTTPServer):
    httpserver.expect_request("/hooks").respond_with_data(b"OK")
    response = tls_requests.get(httpserver.url_for("/hooks"), hooks={"request": [log_request_return]})
    assert response.status_code == 200
    assert response.request.headers.get("X-Hook") == "123456"


def test_request_hook_no_return(httpserver: HTTPServer):
    httpserver.expect_request("/hooks").respond_with_data(b"OK")
    response = tls_requests.get(httpserver.url_for("/hooks"), hooks={"request": [log_request_no_return]})
    assert response.status_code == 200
    assert response.request.headers.get("X-Hook") == "123456"


def test_response_hook(httpserver: HTTPServer):
    httpserver.expect_request(
        "/hooks",
    ).respond_with_data(status=404)
    try:
        _ = tls_requests.get(httpserver.url_for("/hooks"), hooks={"response": [log_response_raise_on_4xx_5xx]})
    except Exception as e:
        assert e, tls_requests.exceptions.HTTPError


def timeout_hook(_request, response):
    time.sleep(3)
    return response


def test_timeout(httpserver: HTTPServer):
    httpserver.expect_request("/timeout").with_post_hook(timeout_hook).respond_with_data(b"OK")
    response = tls_requests.get(httpserver.url_for("/timeout"), timeout=1)
    assert response.status_code == 0
