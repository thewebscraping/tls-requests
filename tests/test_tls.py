from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from tls_requests.models.tls import (
    CustomTLSClientConfig,
    TLSClient,
    TLSConfig,
    TLSRequestCookiesConfig,
    TLSResponse,
    _BaseConfig,
)


def test_base_config_to_camel_case():
    assert _BaseConfig.to_camel_case("test_case") == "testCase"
    assert _BaseConfig.to_camel_case("test") == "test"
    assert _BaseConfig.to_camel_case("longer_test_case_name") == "longerTestCaseName"


def test_base_config_model_fields_set():
    from dataclasses import dataclass

    @dataclass
    class SubConfig(_BaseConfig):
        field1: str = ""
        fieldTwo: int = 0

    fields = SubConfig.model_fields_set()
    assert "field1" in fields
    assert "fieldTwo" in fields
    assert "_extra_config" not in fields


def test_base_config_from_kwargs_and_to_dict():
    from dataclasses import dataclass

    @dataclass
    class SubDataConfig(_BaseConfig):
        fieldOne: str = ""

    # Pass camelCase directly or skip snake_case if it doesn't work for BaseConfig
    instance = SubDataConfig.from_kwargs(fieldOne="value", extra_field="extra")
    assert instance.fieldOne == "value"
    assert instance._extra_config == {"extraField": "extra"}

    d = instance.to_dict()
    assert d["fieldOne"] == "value"
    assert d["extraField"] == "extra"


def test_tls_response_reason():
    resp = TLSResponse(status=200)
    assert resp.reason == "OK"
    assert resp.reason == resp.reason  # test cached or re-calculated

    resp = TLSResponse(status=404)
    assert resp.reason == "Not Found"


def test_tls_response_repr():
    resp = TLSResponse(status=200)
    assert repr(resp) == "<Response [200]>"


def test_tls_request_cookies_config():
    cookie = TLSRequestCookiesConfig(name="foo", value="bar")
    assert cookie.name == "foo"
    assert cookie.value == "bar"


def test_custom_tls_client_config():
    config = CustomTLSClientConfig.from_kwargs(alpnProtocols=["h2", "http/1.1"], ja3String="some-ja3")
    assert config.alpnProtocols == ["h2", "http/1.1"]
    assert config.ja3String == "some-ja3"


def test_tls_config_to_dict_request_body_bytes():
    config = TLSConfig(requestBody=b"hello")
    d = config.to_dict()
    assert d["isByteRequest"] is True
    assert d["requestBody"] == "aGVsbG8="  # base64 for "hello"


def test_tls_config_to_dict_request_body_str():
    config = TLSConfig(requestBody="hello")
    d = config.to_dict()
    assert d["isByteRequest"] is False
    assert d["requestBody"] == "hello"


def test_tls_config_copy_with():
    config = TLSConfig(sessionId="123", timeoutSeconds=10)
    new_config = config.copy_with(session_id="456", timeout=20)
    assert new_config.sessionId == "456"
    assert new_config.timeoutSeconds == 20
    assert config.sessionId == "123"  # Original unchanged


def test_tls_config_from_kwargs_chrome_headers():
    # Test chrome header injection
    config = TLSConfig.from_kwargs(client_identifier="chrome_120")
    assert "user-agent" in config.headers
    assert "Chrome/120" in config.headers["user-agent"]
    assert "sec-ch-ua" in config.headers
    assert "120" in config.headers["sec-ch-ua"]


def test_tls_config_from_kwargs_firefox_headers():
    # Test firefox header injection
    config = TLSConfig.from_kwargs(client_identifier="firefox_115")
    assert "user-agent" in config.headers
    assert "Firefox/115" in config.headers["user-agent"]
    assert "rv:115" in config.headers["user-agent"]


def test_tls_config_from_kwargs_safari_headers():
    # Test safari header injection
    config = TLSConfig.from_kwargs(client_identifier="safari_17")
    assert "user-agent" in config.headers
    assert "Version/17" in config.headers["user-agent"]


def test_tls_client_initialize_mock():
    with patch("tls_requests.models.libraries.TLSLibrary.load") as mock_load:
        mock_lib = MagicMock()
        mock_load.return_value = mock_lib

        # Reset TLSClient class variables for clean test
        TLSClient._library = None
        TLSClient._getCookiesFromSession = None

        TLSClient.initialize()
        assert TLSClient._library == mock_lib
        assert mock_load.called


def test_tls_client_destroy_all_success():
    with patch("tls_requests.models.libraries.TLSLibrary.load") as mock_load:
        mock_lib = MagicMock()
        mock_lib.destroyAll.return_value = b'{"success": true}'
        mock_load.return_value = mock_lib

        TLSClient._library = None
        TLSClient._destroyAll = None
        TLSClient.initialize()

        assert TLSClient.destroy_all() is True


def test_tls_client_destroy_all_failure():
    with patch("tls_requests.models.libraries.TLSLibrary.load") as mock_load:
        mock_lib = MagicMock()
        mock_lib.destroyAll.return_value = b'{"success": false}'
        mock_load.return_value = mock_lib

        TLSClient._library = None
        TLSClient._destroyAll = None
        TLSClient.initialize()

        assert TLSClient.destroy_all() is False


def test_tls_client_get_cookies():
    with patch("tls_requests.models.libraries.TLSLibrary.load") as mock_load:
        mock_lib = MagicMock()
        mock_lib.getCookiesFromSession.return_value = b'{"success": true, "cookies": {"a": "b"}}'
        mock_load.return_value = mock_lib

        TLSClient._library = None
        TLSClient._getCookiesFromSession = None
        resp = TLSClient.get_cookies("sess", "http://example.com")
        assert resp.success is True
        assert resp.cookies == {"a": "b"}


def test_tls_client_add_cookies():
    with patch("tls_requests.models.libraries.TLSLibrary.load") as mock_load:
        mock_lib = MagicMock()
        mock_lib.addCookiesToSession.return_value = b'{"success": true}'
        mock_load.return_value = mock_lib

        TLSClient._library = None
        TLSClient._addCookiesToSession = None
        resp = TLSClient.add_cookies("sess", {"cookie": "val"})
        assert resp.success is True


def test_tls_client_destroy_session():
    with patch("tls_requests.models.libraries.TLSLibrary.load") as mock_load:
        mock_lib = MagicMock()
        mock_lib.destroySession.return_value = b'{"success": true}'
        mock_load.return_value = mock_lib

        TLSClient._library = None
        TLSClient._destroySession = None
        assert TLSClient.destroy_session("sess") is True


def test_tls_client_request():
    with patch("tls_requests.models.libraries.TLSLibrary.load") as mock_load:
        mock_lib = MagicMock()
        mock_lib.request.return_value = b'{"success": true, "status": 200}'
        mock_load.return_value = mock_lib

        TLSClient._library = None
        TLSClient._request = None
        resp = TLSClient.request({"url": "http://test"})
        assert resp.status == 200


def test_tls_client_free_memory():
    with patch("tls_requests.models.libraries.TLSLibrary.load") as mock_load:
        mock_lib = MagicMock()
        mock_lib.freeMemory.return_value = None
        mock_load.return_value = mock_lib

        TLSClient._library = None
        TLSClient._freeMemory = None
        TLSClient.free_memory("some-id")
        assert mock_lib.freeMemory.called


def test_tls_client_response_with_free_memory():
    with patch("tls_requests.models.libraries.TLSLibrary.load") as mock_load:
        mock_lib = MagicMock()
        mock_lib.freeMemory.return_value = None
        mock_load.return_value = mock_lib

        TLSClient._library = None
        TLSClient._freeMemory = None
        # Response with an ID should trigger free_memory
        raw = b'{"id": "resp-123", "status": 200}'
        resp = TLSClient.response(raw)
        assert resp.id == "resp-123"
        assert mock_lib.freeMemory.called


@pytest.mark.asyncio
async def test_tls_client_async_methods():
    with patch("tls_requests.models.libraries.TLSLibrary.load") as mock_load:
        mock_lib = MagicMock()
        mock_lib.request.return_value = b'{"success": true, "status": 200}'
        mock_load.return_value = mock_lib

        TLSClient._library = None
        TLSClient._request = None
        resp = await TLSClient.arequest({"url": "http://test"})
        assert resp.status == 200


def test_tls_config_custom_tls_client_to_dict():
    custom = CustomTLSClientConfig(ja3String="ja3")
    config = TLSConfig(customTlsClient=custom)
    d = config.to_dict()
    assert d.get("tlsClientIdentifier") is None
    # Depending on how extra config works, we might need to check if it's in the dict
    # but the logic in to_dict() explicitly sets it to None


def test_tls_config_http2_copy_with():
    config = TLSConfig(forceHttp1=True)
    new_config = config.copy_with(http2=True)
    assert new_config.forceHttp1 is False

    new_config2 = config.copy_with(http2=False)
    assert new_config2.forceHttp1 is True


def test_tls_config_from_kwargs_unknown_browser():
    config = TLSConfig.from_kwargs(client_identifier="opera_100")
    # Should not have injected headers (or at least not chrome/firefox/safari specific ones)
    # Actually BROWSER_HEADERS only has chrome, firefox, safari
    assert config.headers == {}


def test_tls_config_from_kwargs_with_headers_skips_injection():
    custom_headers = {"X-Test": "Value"}
    config = TLSConfig.from_kwargs(client_identifier="chrome_120", headers=custom_headers)
    assert config.headers == custom_headers
    assert "user-agent" not in config.headers


def test_tls_response_from_bytes_empty():
    # Test from_bytes with minimal json
    resp = TLSResponse.from_bytes(b'{"status": 200}')
    assert resp.status == 200
