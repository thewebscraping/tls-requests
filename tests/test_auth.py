from __future__ import annotations

from base64 import b64encode

import pytest

import tls_requests
from tls_requests.models.auth import Auth, AuthenticationError, BasicAuth

auth = ("user", "pass")
AUTH_TOKEN = "Basic %s" % b64encode(b":".join([s.encode() for s in auth])).decode()
AUTH_HEADERS = {"authorization": AUTH_TOKEN}
AUTH_FUNCTION_KEY = "x-authorization"
AUTH_FUNCTION_VALUE = "123456"
AUTH_FUNCTION_HEADERS = {AUTH_FUNCTION_KEY: AUTH_FUNCTION_VALUE}


def auth_function(request):
    request.headers.update(AUTH_FUNCTION_HEADERS)


@pytest.fixture
def auth_url(httpserver):
    return httpserver.url_for("/auth")


@pytest.fixture
def http_auth_function(httpserver):
    httpserver.expect_request("/auth", headers=AUTH_FUNCTION_HEADERS).respond_with_data()
    return httpserver


@pytest.fixture
def http_auth(httpserver):
    httpserver.expect_request("/auth", headers=AUTH_HEADERS).respond_with_data()
    return httpserver


def test_auth(http_auth, auth_url):
    response = tls_requests.get(auth_url, auth=auth)
    assert response.status_code == 200
    assert response.request.headers["Authorization"] == AUTH_TOKEN


def test_auth_function(http_auth_function, auth_url):
    response = tls_requests.get(auth_url, auth=auth_function)
    assert response.status_code == 200
    assert response.request.headers[AUTH_FUNCTION_KEY] == AUTH_FUNCTION_VALUE


def test_client_auth(http_auth, auth_url):
    with tls_requests.Client(auth=auth) as client:
        response = client.get(auth_url)

    assert response.status_code == 200
    assert bool(response.closed == client.closed) is True
    assert response.request.headers["Authorization"] == AUTH_TOKEN


def test_client_auth_cross_sharing(http_auth, auth_url):
    with tls_requests.Client(auth=("1", "2")) as client:
        response = client.get(auth_url, auth=auth)

    assert response.status_code == 200
    assert bool(response.closed == client.closed) is True
    assert response.request.headers["Authorization"] == AUTH_TOKEN


def test_client_auth_function_cross_sharing(http_auth_function, auth_url):
    with tls_requests.Client(auth=auth) as client:
        response = client.get(auth_url, auth=auth_function)

    assert response.status_code == 200
    assert bool(response.closed == client.closed) is True
    assert response.request.headers[AUTH_FUNCTION_KEY] == AUTH_FUNCTION_VALUE


@pytest.mark.asyncio
async def test_async_auth(http_auth, auth_url):
    async with tls_requests.AsyncClient(auth=auth) as client:
        response = await client.get(auth_url)

    assert response.status_code == 200
    assert bool(response.closed == client.closed) is True
    assert response.request.headers["Authorization"] == AUTH_TOKEN


@pytest.mark.asyncio
async def test_async_auth_function(http_auth_function, auth_url):
    async with tls_requests.AsyncClient(auth=auth_function) as client:
        response = await client.get(auth_url)

    assert response.status_code == 200
    assert bool(response.closed == client.closed) is True
    assert response.request.headers[AUTH_FUNCTION_KEY] == AUTH_FUNCTION_VALUE


@pytest.mark.asyncio
async def test_async_auth_function_cross_sharing(http_auth_function, auth_url):
    async with tls_requests.AsyncClient(auth=auth) as client:
        response = await client.get(auth_url, auth=auth_function)

    assert response.status_code == 200
    assert bool(response.closed == client.closed) is True
    assert response.request.headers[AUTH_FUNCTION_KEY] == AUTH_FUNCTION_VALUE


def test_auth_base():
    a = Auth()
    assert a.build_auth(None) is None


def test_basic_auth_invalid_type():
    with pytest.raises(AuthenticationError):
        b = BasicAuth(123, "pass")
        b._encode(123)
