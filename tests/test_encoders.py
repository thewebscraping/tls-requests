from __future__ import annotations

from mimetypes import guess_type
from pathlib import Path

import pytest
from pytest_httpserver import HTTPServer

import tls_requests

BASE_DIR = Path(__file__).resolve(strict=True).parent.parent

CHUNK_SIZE = 65_536
FILENAME = BASE_DIR / "tests" / "files" / "coingecko.png"


def get_image_bytes(filename: str = FILENAME):
    response_bytes = b""
    with open(filename, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            response_bytes += chunk

    return response_bytes


@pytest.fixture
def mimetype(filename: str = FILENAME):
    return guess_type(filename)[0]


@pytest.fixture
def file_bytes(filename: str = FILENAME) -> bytes:
    return get_image_bytes()


def hook_files(_request, response):
    image = _request.files["image"]
    image_bytes = b"".join(image)
    origin_bytes = get_image_bytes()
    response.headers["X-Image"] = 1 if image_bytes == origin_bytes else 0
    response.headers["X-Image-Content-Type"] = image.content_type
    return response


def hook_multipart(_request, response):
    response.headers["X-Data-Values"] = ", ".join(_request.form.getlist("key1"))
    response.headers["X-Image-Content-Type"] = _request.files["image"].content_type
    return response


def test_file(httpserver: HTTPServer):
    httpserver.expect_request("/files").with_post_hook(hook_files).respond_with_data(status=201)
    files = {"image": open(FILENAME, "rb")}
    response = tls_requests.post(httpserver.url_for("/files"), files=files)
    assert response.status_code == 201
    assert response.headers.get("X-Image") == "1"


def test_file_tuple_2(httpserver: HTTPServer):
    httpserver.expect_request("/files").with_post_hook(hook_files).respond_with_data(status=201)
    files = {"image": ("coingecko.png", open(FILENAME, "rb"))}
    response = tls_requests.post(httpserver.url_for("/files"), files=files)
    assert response.status_code == 201
    assert response.headers.get("X-Image") == "1"


def test_file_tuple_3(httpserver: HTTPServer):
    httpserver.expect_request("/files").with_post_hook(hook_files).respond_with_data(status=201)
    files = {"image": ("coingecko.png", open(FILENAME, "rb"), "image/png")}
    response = tls_requests.post(httpserver.url_for("/files"), files=files)
    assert response.status_code == 201
    assert response.headers.get("X-Image") == "1"
    assert response.headers.get("X-Image-Content-Type") == "image/png"


def test_multipart(httpserver: HTTPServer, file_bytes, mimetype):
    data = {"key1": ["value1", "value2"]}
    httpserver.expect_request("/multipart").with_post_hook(hook_multipart).respond_with_data(status=201)
    files = {"image": ("coingecko.png", open(FILENAME, "rb"), "image/png")}
    response = tls_requests.post(httpserver.url_for("/multipart"), data=data, files=files)
    assert response.status_code == 201
    assert response.headers["X-Image-Content-Type"] == "image/png"
    assert response.headers["X-Data-Values"] == ", ".join(data["key1"])


def test_json(httpserver: HTTPServer):
    data = {"integer": 1, "boolean": True, "list": ["1", "2", "3"], "data": {"key": "value"}}
    httpserver.expect_request("/json", json=data).respond_with_data(b"OK", status=201)
    response = tls_requests.post(httpserver.url_for("/json"), json=data)
    assert response.status_code == 201
    assert response.content == b"OK"
