from pytest_httpserver import HTTPServer
from werkzeug import Request, Response

import tls_requests


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
