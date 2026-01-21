from __future__ import annotations

import tls_requests

RESPONSE_BYTE = b"Hello World!"
RESPONSE_TEXT = "Hello World!"


def assert_response(response):
    assert response.status_code, 200
    assert response.reason, "OK"
    assert response.text, RESPONSE_TEXT
    assert response.content, RESPONSE_BYTE


def make_request(request_fn, httpserver, is_assert_response: bool = True):
    httpserver.expect_request("/api").respond_with_data(RESPONSE_BYTE)
    response = request_fn(httpserver.url_for("/api"))
    if is_assert_response:
        assert_response(response)

    return response


def test_get(httpserver):
    make_request(tls_requests.get, httpserver)


def test_post(httpserver):
    make_request(tls_requests.post, httpserver)


def test_put(httpserver):
    make_request(tls_requests.put, httpserver)


def test_patch(httpserver):
    make_request(tls_requests.patch, httpserver)


def test_delete(httpserver):
    make_request(tls_requests.delete, httpserver)


def test_options(httpserver):
    make_request(tls_requests.options, httpserver)


def test_head(httpserver):
    response = make_request(tls_requests.head, httpserver, False)
    assert response.status_code == 200
    assert response.reason == "OK"
    assert response.text == ""
    assert response.content == b""
