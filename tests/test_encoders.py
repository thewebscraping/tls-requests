from __future__ import annotations

from io import BytesIO
from mimetypes import guess_type
from pathlib import Path

import pytest
from pytest_httpserver import HTTPServer

import tls_requests
from tls_requests.models.encoders import (
    BaseEncoder,
    DataField,
    FileField,
    JsonEncoder,
    MultipartEncoder,
    StreamEncoder,
    format_header,
)

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


def test_format_header_bytes():
    assert format_header("name", b"value") == b'name="value"'


def test_file_field_unpack_variations(tmp_path):
    # Tuple len 1
    f = FileField("test", (BytesIO(b"data"),))
    assert f.filename == "upload"

    # String as value (becomes buffer)
    f2 = FileField("test", "simple string content")
    assert f2.filename == "upload"
    assert f2._buffer.read() == b"simple string content"

    # TextIOWrapper
    p = tmp_path / "test.txt"
    p.write_text("hello")
    with open(p, "r") as tf:
        f3 = FileField("test", tf)
        assert f3.filename == "test.txt"
        assert f3._buffer.read() == b"hello"

    # Invalid buffer type
    with pytest.raises(ValueError):
        FileField("test", 123)


def test_base_encoder_context_manager():
    e = BaseEncoder()
    assert e.closed is False
    with e as entered:
        assert entered is e
    assert e.closed is True


def test_multipart_headers_empty():
    e = MultipartEncoder()
    assert e.headers == {}


def test_stream_encoder_from_bytes():
    e = StreamEncoder.from_bytes(b"raw data")
    assert b"".join(e) == b"raw data"
    assert e.closed is True


def test_base_field_properties():
    f = DataField("foo", "bar")
    assert b"Content-Disposition" in f.headers
    assert b"foo" in f.render_parts()


def test_async_iter_encoder():
    import asyncio

    async def run():
        e = JsonEncoder({"a": 1})
        chunks = []
        async for chunk in e:
            chunks.append(chunk)
        return b"".join(chunks)

    res = asyncio.run(run())
    assert b'{"a":1}' in res
