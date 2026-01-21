# Using Proxies

The `tls_requests` library supports HTTP and SOCKS proxies for routing traffic through an intermediary server. This guide explains how to configure proxies for your client or individual requests.

* * *

## How Proxies Work

Proxies act as intermediaries between your client and the target server. When configured, `tls_requests` routes all network traffic through the specified proxy, which then forwards it to the destination. This is useful for rotating IP addresses, bypassing regional restrictions, or debugging network traffic.

* * *

## Proxy Configuration

### HTTP Proxies

To route traffic through an HTTP proxy, specify the proxy URL in the `proxy` parameter when initializing a `Client`:

```python
import tls_requests

with tls_requests.Client(proxy="http://127.0.0.1:8080") as client:
    response = client.get("https://httpbin.org/ip")
    print(response.json())
```

### SOCKS Proxies

`tls_requests` supports SOCKS5 proxies. Use the `socks5://` scheme in the proxy URL:

```python
import tls_requests

# SOCKS5 without authentication
client = tls_requests.Client(proxy="socks5://127.0.0.1:1080")

# SOCKS5 with authentication
client = tls_requests.Client(proxy="socks5://user:pass@127.0.0.1:1080")
```

### Supported Protocols

*   **HTTP**: `http://`
*   **HTTPS**: `https://`
*   **SOCKS5**: `socks5://`

* * *

## Proxy Authentication

If your proxy requires a username and password, you can include them directly in the proxy URL using the standard format:

```python
proxy_url = "http://username:password@proxy-server.com:8080"
client = tls_requests.Client(proxy=proxy_url)
```

* * *

## Key Considerations

*   **Global vs. Per-Request**: While you usually set a proxy on the `Client`, you can also pass a `proxy` argument to individual request methods if needed.
*   **HTTPS Support**: Both HTTP and SOCKS5 proxies correctly handle HTTPS traffic (using the CONNECT method for HTTP proxies).
*   **Format**: Ensure the proxy URL is a valid string. If you have a `Proxy` object (from `tls_requests.models`), it will be automatically converted to the correct string format.

For advanced use cases where you need to change proxies for every request, see the [Rotators](rotators.md) section.
