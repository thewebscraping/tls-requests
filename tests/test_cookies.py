from __future__ import annotations

from pytest_httpserver import HTTPServer
from werkzeug import Request, Response

import tls_requests


def hook_request_cookies(_request: Request, response: Response) -> Response:
    for k, v in _request.cookies.items():
        response.set_cookie(k, v)
    return response


def hook_response_cookies(_request: Request, response: Response) -> Response:
    response.set_cookie("foo", "bar")
    return response


def test_request_cookies(httpserver: HTTPServer):
    httpserver.expect_request("/cookies").with_post_hook(hook_request_cookies).respond_with_data(b"OK")
    response = tls_requests.get(httpserver.url_for("/cookies"), cookies={"foo": "bar"})
    assert response.status_code == 200
    assert response.cookies.get("foo") == "bar"


def test_response_cookies(httpserver: HTTPServer):
    httpserver.expect_request("/cookies").with_post_hook(hook_response_cookies).respond_with_data(b"OK")
    response = tls_requests.get(httpserver.url_for("/cookies"))
    assert response.status_code == 200
    assert response.cookies.get("foo") == "bar"
