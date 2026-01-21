from __future__ import annotations

import time

from pytest_httpserver import HTTPServer

import tls_requests


def timeout_hook(_request, response):
    time.sleep(3)
    return response


def test_timeout(httpserver: HTTPServer):
    httpserver.expect_request("/timeout").with_post_hook(timeout_hook).respond_with_data(b"OK")
    response = tls_requests.get(httpserver.url_for("/timeout"), timeout=1)
    assert response.status_code == 0
