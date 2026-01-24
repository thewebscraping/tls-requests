from __future__ import annotations

import base64
import datetime
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tls_requests.client import AsyncClient, BaseClient, Client, ClientState
from tls_requests.exceptions import AuthenticationError, ProxyError, RemoteProtocolError, TooManyRedirects
from tls_requests.models import (
    URL,
    Auth,
    HeaderRotator,
    Headers,
    Proxy,
    ProxyRotator,
    Request,
    Response,
    TLSIdentifierRotator,
)
from tls_requests.models.cookies import Cookies, RequestsCookieJar
from tls_requests.models.tls import TLSClient, TLSConfig, TLSResponse, _BaseConfig
from tls_requests.settings import DEFAULT_CLIENT_IDENTIFIER

VALID_B64_BODY = base64.b64encode(b'{"ok": true}').decode()


def test_cookies_extra_coverage():
    jar = RequestsCookieJar()
    expires = time.time() + 3600
    jar.set("a", "b", expires=expires)
    assert jar.get("a") == "b"

    cookies = Cookies()
    cookies.set("x", "y")
    assert cookies["x"] == "y"


def test_urls_extra_coverage():
    u = URL("https://user:pass@host:8080/path?a=b#hash")
    assert u.username == "user"
    assert u.password == "pass"


def test_client_hooks_none():
    client = BaseClient()
    assert client._rebuild_hooks(None) is None


def test_client_hooks_empty_dict():
    client = BaseClient()
    assert client._rebuild_hooks({}) == {}


def test_client_redirect_no_location():
    client = Client()
    req = MagicMock()
    req.url = URL("https://host")
    resp = MagicMock()
    resp.headers = {}
    with pytest.raises(RemoteProtocolError, match="without 'Location'"):
        client._rebuild_redirect_url(req, resp)


def test_client_redirect_invalid_location_final():
    client = Client()
    req = MagicMock()
    req.url = URL("https://host")
    resp = MagicMock()
    resp.headers = {"Location": "http://other"}
    with patch("tls_requests.client.URL") as mock_url_cls:
        mock_url = MagicMock()
        mock_url.netloc = "other"
        mock_url.scheme = "https"
        mock_url.url = ""
        mock_url_cls.return_value = mock_url
        with pytest.raises(RemoteProtocolError, match="Invalid URL in Location headers"):
            client._rebuild_redirect_url(req, resp)


def test_response_private_stream_consumed():
    resp = Response(200)
    assert resp._is_stream_consumed is False
    resp._is_stream_consumed = True
    assert resp._is_stream_consumed is True


def test_auth_extra_coverage():
    from tls_requests.models.auth import BasicAuth

    auth = BasicAuth(123, 456)
    with pytest.raises(AuthenticationError):
        auth.build_auth(MagicMock())


def test_cookies_get_dict_missing_branches_final():
    jar = RequestsCookieJar()
    res = jar.get_dict(domain="example.com", path="/")
    assert isinstance(res, dict)


def test_utils_to_str_final():
    from tls_requests.utils import to_str

    assert to_str(None) == ""
    assert to_str(123) == "123"
    assert to_str([1, 2]) == "[1,2]"


def test_client_auth_request_coverage():
    def my_auth(request):
        return request

    with patch("tls_requests.client.TLSClient.request") as mock_request:
        mock_request.return_value = TLSResponse(success=True, status=200, body=VALID_B64_BODY)
        client = Client(auth=my_auth)
        client.get("http://example.com")


@pytest.mark.asyncio
async def test_aclient_auth_request_coverage():
    def my_auth(request):
        return request

    with patch("tls_requests.client.TLSClient.arequest") as mock_request:
        mock_request.return_value = TLSResponse(success=True, status=200, body=VALID_B64_BODY)
        async with AsyncClient(auth=my_auth) as client:
            await client.get("http://example.com")


def test_client_redirect_303():
    with patch("tls_requests.client.TLSClient.request") as mock_request:
        mock_request.side_effect = [
            TLSResponse(success=True, status=303, headers={"Location": "/new"}),
            TLSResponse(success=True, status=200, body=VALID_B64_BODY),
        ]
        client = Client(follow_redirects=True)
        resp = client.post("http://example.com/old")
        assert resp.request.method == "GET"


def test_client_redirect_301_post():
    with patch("tls_requests.client.TLSClient.request") as mock_request:
        mock_request.side_effect = [
            TLSResponse(success=True, status=301, headers={"Location": "/new"}),
            TLSResponse(success=True, status=200, body=VALID_B64_BODY),
        ]
        client = Client(follow_redirects=True)
        resp = client.post("http://example.com/old")
        assert resp.request.method == "GET"


@pytest.mark.asyncio
async def test_aclient_response_hook_coverage():
    def my_hook(response):
        return response

    with patch("tls_requests.client.TLSClient.arequest") as mock_request:
        mock_request.return_value = TLSResponse(success=True, status=200, body=VALID_B64_BODY)
        async with AsyncClient(hooks={"response": [my_hook]}) as client:
            await client.get("http://example.com")


def test_build_hook_response_none_coverage():
    client = Client(hooks={"response": []})  # empty sequence
    req = Request("GET", "http://example.com")
    resp = Response(status_code=200)
    resp.request = req
    assert client.build_hook_response(resp) is None


def test_client_request_hook_returns_request():
    def my_hook(request):
        request.headers["X-Custom"] = "hooked"
        return request

    with patch("tls_requests.client.TLSClient.request") as mock_request:
        mock_request.return_value = TLSResponse(success=True, status=200, body=VALID_B64_BODY)
        client = Client(hooks={"request": [my_hook]})
        resp = client.get("http://example.com")
        assert resp.request.headers["X-Custom"] == "hooked"


@pytest.mark.asyncio
async def test_aclient_request_hook_returns_request():
    def my_hook(request):
        request.headers["X-Custom"] = "hooked"
        return request

    with patch("tls_requests.client.TLSClient.arequest") as mock_request:
        mock_request.return_value = TLSResponse(success=True, status=200, body=VALID_B64_BODY)
        async with AsyncClient(hooks={"request": [my_hook]}) as client:
            resp = await client.get("http://example.com")
            # Line 1204 in client.py
            assert resp.request.headers["X-Custom"] == "hooked"


def test_client_redirect_302_get():
    with patch("tls_requests.client.TLSClient.request") as mock_request:
        mock_request.side_effect = [
            TLSResponse(success=True, status=302, headers={"Location": "/new"}),
            TLSResponse(success=True, status=200, body=VALID_B64_BODY),
        ]
        client = Client(follow_redirects=True)
        resp = client.post("http://example.com/old", data={"a": 1})
        assert resp.status_code == 200
        assert resp.history[0].status_code == 302
        assert resp.request.method == "GET"  # 302 POST -> GET


def test_client_redirect_scheme_mismatch():
    client = Client()
    req = Request("GET", "http://example.com")
    resp = Response(status_code=301, headers={"Location": "https://example.com/new"})
    resp.request = req

    new_req = client._rebuild_redirect_request(req, resp)
    assert new_req.url.scheme == "http"  # line 425 covers this


def test_client_proxy_rotator_marking():
    rotator = ProxyRotator(["http://proxy1:8080"])
    with patch("tls_requests.client.TLSClient.request") as mock_request:
        mock_request.return_value = TLSResponse(success=True, status=200, body=VALID_B64_BODY)
        client = Client(proxy=rotator)
        with patch.object(rotator, "mark_result") as mock_mark:
            client.get("http://example.com")
            assert mock_mark.called


@pytest.mark.asyncio
async def test_aclient_proxy_rotator_marking():
    rotator = ProxyRotator(["http://proxy1:8080"])
    with patch("tls_requests.client.TLSClient.arequest") as mock_request:
        mock_request.return_value = TLSResponse(success=True, status=200, body=VALID_B64_BODY)
        async with AsyncClient(proxy=rotator) as client:
            with patch.object(rotator, "amark_result", new_callable=AsyncMock) as mock_mark:
                await client.get("http://example.com")
                assert mock_mark.called


@pytest.mark.asyncio
async def test_aclient_redirect_too_many():
    with patch("tls_requests.client.TLSClient.arequest") as mock_request:
        mock_request.return_value = TLSResponse(
            success=True, status=302, headers={"Location": "http://example.com/loop"}
        )
        async with AsyncClient(follow_redirects=True, max_redirects=1) as client:
            with pytest.raises(TooManyRedirects):
                await client.get("http://example.com/loop")


@pytest.mark.asyncio
async def test_aclient_enter_errors():
    client = AsyncClient()
    async with client:
        with pytest.raises(RuntimeError, match="not possible to open a client instance more than once"):
            await client.__aenter__()

    with pytest.raises(RuntimeError, match="cannot be reopened after it has been closed"):
        await client.__aenter__()


def test_tls_config_to_payload():
    config = TLSConfig()
    assert config.to_payload() == config.to_dict()


def test_tls_initialize_in_init():
    with patch("tls_requests.models.tls.TLSLibrary.load") as mock_load:
        TLSClient._library = None
        TLSClient()
        assert mock_load.called


def test_tls_initialize_in_destroy_all():
    with patch("tls_requests.models.tls.TLSLibrary.load") as mock_load:
        mock_lib = MagicMock()
        mock_lib.destroyAll.return_value = b'{"success": true}'
        mock_load.return_value = mock_lib

        TLSClient._library = None
        TLSClient._destroyAll = None
        TLSClient.destroy_all()
        assert mock_load.called


def test_tls_initialize_return():
    with patch("tls_requests.models.tls.TLSLibrary.load"):
        TLSClient._library = None
        res = TLSClient.initialize()
        assert isinstance(res, TLSClient)


def test_tls_destroy_all_fail():
    with patch("tls_requests.models.tls.TLSClient._destroyAll") as mock_destroy:
        mock_destroy.return_value = b'{"success": false}'
        assert TLSClient.destroy_all() is False


def test_base_config_from_kwargs():
    config = _BaseConfig.from_kwargs(extra_param="value")
    assert hasattr(config, "_extra_config")


def test_tls_config_stream_id():
    config = TLSConfig.from_kwargs(stream_id=123)
    assert config.streamID == 123


def test_base_client_deprecated_tls_identifier():
    with patch("tls_requests.client.TLSClient.initialize"):
        client = BaseClient(tls_identifier="custom_chrome")
        # client_identifier should be set from tls_identifier
        assert client._config.tlsClientIdentifier == "custom_chrome"


def test_base_client_headers_initialization():
    with patch("tls_requests.client.TLSClient.initialize"):
        # Test rotator
        rotator = HeaderRotator([])
        client = BaseClient(headers=rotator)
        assert client._header_rotator == rotator

        # Test list (converted to rotator)
        with patch("tls_requests.models.HeaderRotator.from_file") as mock_from_file:
            BaseClient(headers=["file.json"])
            mock_from_file.assert_called_with(["file.json"])


def test_base_client_properties_and_setters():
    with patch("tls_requests.client.TLSClient.initialize"):
        client = BaseClient()

        # closed
        assert client.closed is False
        client._state = ClientState.CLOSED
        assert client.closed is True

        # headers setter
        rotator = HeaderRotator([])
        client.headers = rotator
        assert client._header_rotator == rotator

        client.headers = {"a": "b"}
        assert client.headers["a"] == "b"

        with patch("tls_requests.models.HeaderRotator.from_file") as mock_from_file:
            client.headers = ["file.json"]
            mock_from_file.assert_called()

        # cookies setter
        client.cookies = {"c": "d"}
        assert client.cookies["c"] == "d"

        # params setter
        client.params = {"p": "v"}
        assert client.params["p"] == "v"

        # hooks setter
        def dummy_hook(r):
            return r

        client.hooks = {"request": [dummy_hook]}
        assert client.hooks["request"] == [dummy_hook]


def test_prepare_auth():
    with patch("tls_requests.client.TLSClient.initialize"):
        client = BaseClient()
        req = MagicMock(spec=Request)
        req.headers = {}

        # Tuple auth
        client.prepare_auth(req, ("user", "pass"))
        assert "Authorization" in req.headers

        # Callable auth
        mock_auth_func = MagicMock()
        client.prepare_auth(req, mock_auth_func)
        mock_auth_func.assert_called_with(req)

        # Auth instance
        class MyAuth(Auth):
            def build_auth(self, request):
                return "authorized"

        auth_inst = MyAuth()
        assert client.prepare_auth(req, auth_inst) == "authorized"


def test_prepare_headers_rotator():
    with patch("tls_requests.client.TLSClient.initialize"):
        client = BaseClient()
        rotator = MagicMock(spec=HeaderRotator)
        rotator.next.return_value = Headers({"X-Rotated": "1"})

        # Client rotator
        client._header_rotator = rotator
        res = client.prepare_headers()
        assert res["X-Rotated"] == "1"

        # Specific rotator
        res2 = client.prepare_headers(headers=rotator)
        assert res2["X-Rotated"] == "1"


def test_prepare_proxy_types():
    with patch("tls_requests.client.TLSClient.initialize"):
        client = BaseClient()

        # None
        assert client.prepare_proxy(None) is None

        # ProxyRotator
        rotator = MagicMock(spec=ProxyRotator)
        rotator.next.return_value = "http://proxy:8080"
        res = client.prepare_proxy(rotator)
        assert res.url == "http://proxy:8080"

        # String/Bytes
        assert client.prepare_proxy("http://host:80").url == "http://host:80"

        # Proxy instance
        p = Proxy("http://p")
        assert client.prepare_proxy(p) == p

        # URL instance
        u = URL("http://u")
        assert client.prepare_proxy(u).url == "http://u"

        # Invalid
        with pytest.raises(ProxyError):
            client.prepare_proxy(123)


def test_prepare_client_identifier_rotator():
    with patch("tls_requests.client.TLSClient.initialize"):
        client = BaseClient()
        rotator = MagicMock(spec=TLSIdentifierRotator)
        rotator.next.return_value = "chrome_99"
        assert client.prepare_client_identifier(rotator) == "chrome_99"


def test_rebuild_hooks_edge_cases():
    with patch("tls_requests.client.TLSClient.initialize"):
        client = BaseClient()
        # Invalid keys or non-callable items
        hooks = {"invalid": [lambda x: x], "request": ["not_callable"]}
        rebuilt = client._rebuild_hooks(hooks)
        assert "invalid" not in rebuilt
        assert rebuilt["request"] == []


def test_redirect_url_errors():
    with patch("tls_requests.client.TLSClient.initialize"):
        client = BaseClient()
        req = MagicMock(spec=Request)
        req.url = URL("https://example.com")

        # Missing Location
        resp_no_loc = MagicMock(spec=Response)
        resp_no_loc.headers = {}
        with pytest.raises(RemoteProtocolError, match="without 'Location'"):
            client._rebuild_redirect_url(req, resp_no_loc)

        # Invalid URL in Location
        resp_bad_loc = MagicMock(spec=Response)
        resp_bad_loc.headers = {"Location": "http://[invalid]"}
        with pytest.raises(RemoteProtocolError, match="Invalid URL"):
            client._rebuild_redirect_url(req, resp_bad_loc)


def test_redirect_url_netloc_missing():
    with patch("tls_requests.client.TLSClient.initialize"):
        client = BaseClient()
        req = MagicMock(spec=Request)
        req.url = URL("https://host:443/path")

        resp = MagicMock(spec=Response)
        resp.headers = {"Location": "/newpath"}

        url = client._rebuild_redirect_url(req, resp)
        assert url.host == "host"
        assert url.scheme == "https"
        assert str(url.port) == "443"


def test_redirect_scheme_change_h2_error():
    with patch("tls_requests.client.TLSClient.initialize"):
        # http2='http2' forces it to not be 'auto' or None
        client = BaseClient(http2="http2")
        req = MagicMock(spec=Request)
        req.url = URL("https://host")

        resp = MagicMock(spec=Response)
        resp.headers = {"Location": "http://otherhost"}  # Switch to http

        with pytest.raises(RemoteProtocolError, match="Switching remote scheme from HTTP/2 to HTTP/1"):
            client._rebuild_redirect_url(req, resp)


def test_lifecycle_errors():
    with patch("tls_requests.client.TLSClient.initialize"):
        client = BaseClient()
        client._state = ClientState.OPENED
        with pytest.raises(RuntimeError, match="more than once"):
            client.__enter__()

        client._state = ClientState.CLOSED
        with pytest.raises(RuntimeError, match="cannot be reopened"):
            client.__enter__()


@pytest.mark.asyncio
async def test_async_client_proxy_rotator_mark():
    with patch("tls_requests.client.TLSClient.initialize"):
        rotator = MagicMock(spec=ProxyRotator)
        client = AsyncClient(proxy=rotator)

        req = MagicMock(spec=Request)
        req.proxy = Proxy("http://p")

        resp = MagicMock(spec=Response)
        resp.status_code = 200
        resp.elapsed = datetime.timedelta(seconds=1)
        resp.request = req
        resp.is_redirect = False

        with patch.object(AsyncClient, "_send", return_value=resp):
            await client.send(req)
            rotator.amark_result.assert_called()


def test_client_all_request_methods():
    with patch("tls_requests.client.TLSClient.initialize"):
        client = Client()
        # Mock _send to avoid actual requests
        mock_resp = MagicMock(spec=Response)
        mock_resp.status_code = 200
        mock_resp.is_redirect = False
        mock_resp.request = MagicMock(spec=Request)
        mock_resp.request.proxy = None

        with patch.object(Client, "_send", return_value=mock_resp):
            client.get("https://test")
            client.post("https://test")
            client.put("https://test")
            client.patch("https://test")
            client.delete("https://test")
            client.head("https://test")
            client.options("https://test")


@pytest.mark.asyncio
async def test_async_client_all_request_methods():
    with patch("tls_requests.client.TLSClient.initialize"):
        client = AsyncClient()
        mock_resp = MagicMock(spec=Response)
        mock_resp.status_code = 200
        mock_resp.is_redirect = False
        mock_resp.request = MagicMock(spec=Request)
        mock_resp.request.proxy = None

        with patch.object(AsyncClient, "_send", return_value=mock_resp):
            await client.get("https://test")
            await client.post("https://test")
            await client.put("https://test")
            await client.patch("https://test")
            await client.delete("https://test")
            await client.head("https://test")
            await client.options("https://test")


def test_client_send_closed():
    with patch("tls_requests.client.TLSClient.initialize"):
        client = Client()
        client.close()
        with pytest.raises(RuntimeError, match="client has been closed"):
            client.get("https://test")


def test_client_with_hooks():
    with patch("tls_requests.client.TLSClient.initialize"):
        req_hook_called = False
        resp_hook_called = False

        def req_hook(r):
            nonlocal req_hook_called
            req_hook_called = True
            return r

        def resp_hook(resp):
            nonlocal resp_hook_called
            resp_hook_called = True
            return resp

        client = Client(hooks={"request": [req_hook], "response": [resp_hook]})
        mock_resp = MagicMock(spec=Response)
        mock_resp.status_code = 200
        mock_resp.is_redirect = False
        mock_resp.request = MagicMock(spec=Request)
        mock_resp.request.proxy = None

        with patch.object(Client, "_send", return_value=mock_resp):
            client.get("https://test")
            assert req_hook_called is True
            assert resp_hook_called is True


def test_redirect_limit():
    with patch("tls_requests.client.TLSClient.initialize"):
        client = Client(max_redirects=2)

        # We need to mock the TLSClient response precisely to avoid decoding errors
        with patch.object(Client, "session") as mock_session:
            # Return redirect response repeatedly
            mock_tls_resp = MagicMock()
            mock_tls_resp.status = 302
            mock_tls_resp.headers = {"Location": "https://test2"}
            mock_tls_resp.body = "data:text/plain;base64,YWJj"  # "abc"
            mock_tls_resp.cookies = {}
            mock_tls_resp.id = "1"
            mock_tls_resp.target = "https://test1"
            mock_tls_resp.success = True
            mock_tls_resp.usedProtocol = "HTTP/1.1"

            mock_session.request.return_value = mock_tls_resp

            with pytest.raises(TooManyRedirects):
                client.get("https://test1")


@pytest.mark.asyncio
async def test_async_redirect_limit():
    with patch("tls_requests.client.TLSClient.initialize"):
        client = AsyncClient(max_redirects=2)

        with patch.object(AsyncClient, "session") as mock_session:
            mock_tls_resp = MagicMock()
            mock_tls_resp.status = 302
            mock_tls_resp.headers = {"Location": "https://test2"}
            mock_tls_resp.body = "data:text/plain;base64,YWJj"
            mock_tls_resp.cookies = {}
            mock_tls_resp.id = "1"
            mock_tls_resp.target = "https://test1"
            mock_tls_resp.success = True
            mock_tls_resp.usedProtocol = "HTTP/1.1"

            # Use AsyncMock for arequest
            mock_session.arequest = AsyncMock(return_value=mock_tls_resp)

            with pytest.raises(TooManyRedirects):
                await client.get("https://test1")


@pytest.mark.asyncio
async def test_async_client_send_closed():
    with patch("tls_requests.client.TLSClient.initialize"):
        client = AsyncClient()
        await client.aclose()
        with pytest.raises(RuntimeError, match="client has been closed"):
            await client.get("https://test")


def test_prepare_client_identifier_default():
    with patch("tls_requests.client.TLSClient.initialize"):
        client = BaseClient()
        assert client.prepare_client_identifier(None) == str(DEFAULT_CLIENT_IDENTIFIER)


def test_prepare_headers_basic():
    with patch("tls_requests.client.TLSClient.initialize"):
        client = BaseClient()
        # Coverage for line 261
        res = client.prepare_headers(headers={"X-Test": "1"})
        assert res["X-Test"] == "1"


def test_redirect_url_scheme_http_to_http():
    with patch("tls_requests.client.TLSClient.initialize"):
        client = BaseClient()
        req = MagicMock(spec=Request)
        req.url = URL("http://host")

        resp = MagicMock(spec=Response)
        resp.headers = {"Location": "http://otherhost"}

        # Coverage for line 425
        url = client._rebuild_redirect_url(req, resp)
        assert url.scheme == "http"


def test_redirect_url_invalid_final_check():
    with patch("tls_requests.client.TLSClient.initialize"):
        client = BaseClient()
        req = MagicMock(spec=Request)
        req.url = URL("https://host")

        resp = MagicMock(spec=Response)
        resp.headers = {"Location": "https://otherhost"}

        # Simulate url.url being empty after processing
        with patch("tls_requests.client.URL") as mock_url_cls:
            mock_url = MagicMock()
            mock_url.netloc = "otherhost"
            mock_url.scheme = "https"
            mock_url.url = ""  # Coverage for line 438
            mock_url_cls.return_value = mock_url

            with pytest.raises(RemoteProtocolError, match="Invalid URL in Location headers"):
                client._rebuild_redirect_url(req, resp)


@pytest.mark.asyncio
async def test_async_prepare_methods():
    with patch("tls_requests.client.TLSClient.initialize"):
        rotator = MagicMock(spec=HeaderRotator)
        rotator.anext = AsyncMock(return_value=Headers({"X-Async": "1"}))

        client = AsyncClient(headers=rotator)

        # aprepare_headers
        h1 = await client.aprepare_headers()
        assert h1["X-Async"] == "1"

        h2 = await client.aprepare_headers(headers=rotator)
        assert h2["X-Async"] == "1"

        h3 = await client.aprepare_headers(headers={"X": "Y"})
        assert h3["X"] == "Y"

        # aprepare_proxy
        client.proxy = "http://p"
        assert (await client.aprepare_proxy(None)) is None
        assert (await client.aprepare_proxy("http://p2")).url == "http://p2"

        # Coverage for line 882-886 (Proxy and URL types)
        assert (await client.aprepare_proxy(Proxy("http://p3"))).url == "http://p3"
        assert (await client.aprepare_proxy(URL("http://p4"))).url == "http://p4"
        with pytest.raises(ProxyError):
            await client.aprepare_proxy(123)

        # aprepare_client_identifier
        assert await client.aprepare_client_identifier("chrome") == "chrome"

        id_rotator = MagicMock(spec=TLSIdentifierRotator)
        id_rotator.anext = AsyncMock(return_value="firefox")
        assert await client.aprepare_client_identifier(id_rotator) == "firefox"

        assert await client.aprepare_client_identifier(None) == DEFAULT_CLIENT_IDENTIFIER


def test_redirect_scheme_change_auto():
    with patch("tls_requests.client.TLSClient.initialize"):
        # http2='auto' allows session reset
        client = BaseClient(http2="auto")
        old_session_id = client._config.sessionId

        req = MagicMock(spec=Request)
        req.url = URL("https://host")

        resp = MagicMock(spec=Response)
        resp.headers = {"Location": "http://otherhost"}

        url = client._rebuild_redirect_url(req, resp)
        assert url.scheme == "http"
        assert client._config.sessionId != old_session_id
        # session.destroy_session should be called for old session
        client.session.destroy_session.assert_called_with(old_session_id)


def test_base_client_headers_list_init():
    with patch("tls_requests.client.TLSClient.initialize"):
        with patch("tls_requests.models.HeaderRotator.from_file"):
            client = BaseClient(headers=["list"])
            assert client._header_rotator is not None


def test_base_client_init_headers_dict():
    with patch("tls_requests.client.TLSClient.initialize"):
        client = BaseClient(headers={"a": "b"})
        assert client.headers["a"] == "b"


@pytest.mark.asyncio
async def test_async_client_send_with_auth_and_rotator():
    with patch("tls_requests.client.TLSClient.initialize"):
        rotator = AsyncMock(spec=ProxyRotator)
        rotator.anext.return_value = Proxy("http://proxyhost:8080")
        rotator.amark_result = AsyncMock()

        client = AsyncClient(proxy=rotator, auth=("user", "pass"))

        req = MagicMock(spec=Request)
        req.proxy = Proxy("http://p")
        req.headers = {}

        resp = MagicMock(spec=Response)
        resp.status_code = 200
        resp.elapsed = datetime.timedelta(seconds=1)
        resp.request = req
        resp.is_redirect = False
        resp.read = AsyncMock()
        resp.aread = AsyncMock()
        resp.close = AsyncMock()
        resp.aclose = AsyncMock()

        with patch.object(AsyncClient, "_send", return_value=resp):
            await client.get("https://test")
            rotator.amark_result.assert_called()


def test_base_client_exit_reentry_errors():
    with patch("tls_requests.client.TLSClient.initialize"):
        client = BaseClient()
        with client:
            pass
        # client is now closed
        with pytest.raises(RuntimeError, match="cannot be reopened"):
            with client:
                pass


@pytest.mark.asyncio
async def test_async_client_proxy_rotator_failure_mark():
    with patch("tls_requests.client.TLSClient.initialize"):
        rotator = MagicMock(spec=ProxyRotator)
        rotator.amark_result = AsyncMock()
        client = AsyncClient(proxy=rotator)

        req = MagicMock(spec=Request)
        req.proxy = Proxy("http://p")

        resp = MagicMock(spec=Response)
        resp.status_code = 500
        resp.elapsed = datetime.timedelta(seconds=1)
        resp.request = req
        resp.is_redirect = False

        with patch.object(AsyncClient, "_send", return_value=resp):
            await client.send(req)
            # Verify success=False was passed
            rotator.amark_result.assert_called_with(proxy=req.proxy, success=False, latency=1.0)


@pytest.mark.asyncio
async def test_async_client_context_manager_autoclose():
    with patch("tls_requests.client.TLSClient.initialize"):
        async with AsyncClient() as client:
            session_id = client._config.sessionId
            mock_session = client.session
            assert client.closed is False

        mock_session.destroy_session.assert_called_with(session_id)
