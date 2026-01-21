from __future__ import annotations

import tls_requests
from tls_requests.models.tls import TLSConfig


def test_protocol_racing_parameters():
    # Test passing protocol_racing to Client and request
    with tls_requests.Client(protocol_racing=True) as client:
        assert client.protocol_racing is True
        # We can't easily verify the actual network behavior without a specialized mock
        # but we can check if it's passed correctly to the config

    resp = tls_requests.get("https://httpbin.org/get", protocol_racing=True)
    assert resp.status_code == 200


def test_allow_http_parameters():
    # Test with_allow_http
    with tls_requests.Client(allow_http=True) as client:
        assert client.allow_http is True

    # Test request parameter
    resp = tls_requests.get("https://httpbin.org/get", allow_http=True)
    assert resp.status_code == 200


def test_stream_id_parameters():
    # Test stream_id
    with tls_requests.Client(stream_id=1) as client:
        assert client.stream_id == 1


def test_extra_kwargs_persistence():
    # Test that extra kwargs are preserved in TLSConfig
    config = TLSConfig.from_kwargs(local_address="127.0.0.1", random_extra="value")
    payload = config.to_payload()
    assert payload.get("localAddress") == "127.0.0.1"
    assert payload.get("randomExtra") == "value"


def test_client_initialization_with_extra_kwargs():
    # Test passing extra kwargs to Client
    with tls_requests.Client(local_address="127.0.0.1") as client:
        # Check if the internal config has it
        payload = client._config.to_payload()
        assert payload.get("localAddress") == "127.0.0.1"
