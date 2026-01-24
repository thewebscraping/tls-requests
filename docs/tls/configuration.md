# TLS Configuration

The `tls_requests` library allows for deep customization of the TLS stack. This is achieved through the `TLSConfig` and `CustomTLSClientConfig` classes.

* * *

## TLSConfig

The `TLSConfig` class provides a structured way to configure TLS-specific settings for HTTP requests. It supports features like custom headers, cookie handling, proxy configuration, and advanced TLS session options.

### Example: Manual Configuration

You can initialize a `TLSConfig` object to fine-tune request behavior:

```python
import tls_requests

config_data = {
    "catchPanics": False,
    "followRedirects": False,
    "forceHttp1": False,
    "headers": {
        "accept": "text/html,application/xhtml+xml",
        "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/105.0.0.0 Safari/537.36",
    },
    "insecureSkipVerify": False,
    "proxyUrl": "",
    "requestMethod": "GET",
    "requestUrl": "https://httpbin.org/get",
    "sessionId": "my-custom-session",
    "timeoutSeconds": 30,
    "tlsClientIdentifier": "chrome_120",
}

config = tls_requests.TLSConfig.from_kwargs(**config_data)
# Use the config in a request
response = tls_requests.get("https://httpbin.org/get", **config.to_dict())
```

* * *

## Custom TLS Client Configuration

The `CustomTLSClientConfig` class defines advanced options for emulating specific client behaviors at the protocol level. This includes ALPN, HTTP/2 settings, and JA3 fingerprints.

### Advanced Example: Hardening Fingerprints

```python
import tls_requests

advanced_config = {
    "alpnProtocols": ["h2", "http/1.1"],
    "certCompressionAlgo": "brotli",
    "h2Settings": {
        "HEADER_TABLE_SIZE": 65536,
        "MAX_CONCURRENT_STREAMS": 1000,
        "INITIAL_WINDOW_SIZE": 6291456,
        "MAX_HEADER_LIST_SIZE": 262144
    },
    "ja3String": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0",
    "keyShareCurves": ["X25519"],
    "priorityFrames": [],
    "pseudoHeaderOrder": [
        ":method",
        ":authority",
        ":scheme",
        ":path"
    ],
    "supportedSignatureAlgorithms": [
        "ECDSAWithP256AndSHA256",
        "PSSWithSHA256",
        "PKCS1WithSHA256",
        "ECDSAWithP384AndSHA384",
        "PSSWithSHA384",
        "PKCS1WithSHA384",
        "PSSWithSHA512",
        "PKCS1WithSHA512"
    ],
    "supportedVersions": [
        "GREASE",
        "1.3",
        "1.2"
    ]
}

custom_config = tls_requests.CustomTLSClientConfig(**advanced_config)
# Pass this to your TLSConfig
config_obj = tls_requests.TLSConfig(customTlsClient=custom_config)
response = tls_requests.get("https://httpbin.org/get", **config_obj.to_dict())
```

By leveraging these configuration classes, you can achieve highly specific TLS fingerprints to match any browser or specialized client requirement.

!!! note
    When using `CustomTLSClientConfig`, the `tlsClientIdentifier` parameter in TLSConfig is set to None.

### Passing Request Parameters Directly

```python
import tls_requests
r = tls_requests.get(
    url = "https://httpbin.org/get",
    proxy = "http://127.0.0.1:8080",
    http2 = True,
    timeout = 10.0,
    follow_redirects = True,
    verify = True,
    client_identifier = "chrome_120",
    **config_obj.to_dict(),
)
r
<Response [200 OK]>
```

!!! note
    When using the `customTlsClient` parameter within `**config_obj.to_dict()`, the `client_identifier` parameter will not be set.
    Parameters such as `headers`, `cookies`, `proxy`, `timeout`, `verify`, and `client_identifier` will override the existing configuration in TLSConfig.

### `Client` and `AsyncClient` Parameters
```python
import tls_requests
client = tls_requests.Client(
    proxy = "http://127.0.0.1:8080",
    http2 = True,
    timeout = 10.0,
    follow_redirects = True,
    verify = True,
    client_identifier = "chrome_120",
    **config_obj.to_dict(),
)
r = client.get(url = "https://httpbin.org/get",)
r
<Response [200 OK]>
```

!!! note
    The `Client` and `AsyncClient` interfaces in `tls_requests` enable reusable and shared configurations for multiple requests, providing a more convenient and efficient approach for handling HTTP requests.
