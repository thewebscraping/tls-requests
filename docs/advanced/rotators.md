# Using Rotators

The `tls_requests` library is designed to be smart out of the box. By default, it automatically rotates through realistic headers and client identifiers to make your requests appear authentic and avoid detection.

This guide explains how these default rotators work and how you can customize or disable them.

* * *

### Header Rotator

**Default Behavior: Automatic Rotation**

When you initialize a `Client` without specifying the `headers` parameter, it will **automatically rotate** through a built-in collection of header templates that mimic popular browsers like Chrome, Firefox, and Safari across different operating systems.

```python
import tls_requests

# No extra configuration needed!
# This client will automatically use a different, realistic header set for each request.
with tls_requests.Client(headers=tls_requests.HeaderRotator()) as client:
    # Request 1 might have Chrome headers
    res1 = client.get("https://httpbin.org/headers")
    print(f"Request 1 UA: {res1.json()['headers']['User-Agent']}")

    # Request 2 might have Firefox headers
    res2 = client.get("https://httpbin.org/headers")
    print(f"Request 2 UA: {res2.json()['headers']['User-Agent']}")
```

**How to Override the Default Behavior:**

-   **To rotate through your own list of headers**, pass a `list` of `dict`s:
    ```python
    my_headers = [{"User-Agent": "MyBot/1.0"}, {"User-Agent": "MyBot/2.0"}]
    client = tls_requests.Client(headers=my_headers)
    ```

-   **To use a single, static set of headers (no rotation)**, pass a single `dict`:
    ```python
    static_headers = {"User-Agent": "Always-The-Same-Bot/1.0"}
    client = tls_requests.Client(headers=static_headers)
    ```

-   **To completely disable default headers**, pass `None`:
    ```python
    # This client will not add any default headers (like User-Agent).
    client = tls_requests.Client(headers=None)
    ```

* * *

### TLS Client Identifier Rotator

**Default Behavior: Automatic Rotation**

Similar to headers, the `Client` **defaults to rotating** through all supported client identifier profiles (e.g., `chrome_120`, `firefox_120`, `safari_16_0`, etc.). This changes your TLS fingerprint with every request, an advanced technique to evade sophisticated anti-bot systems.

```python
import tls_requests

# This client automatically changes its TLS fingerprint for each request.
with tls_requests.Client(client_identifier=tls_requests.TLSIdentifierRotator()) as client:
    # These two requests will have different TLS profiles.
    res1 = client.get("https://tls.browserleaks.com/json")
    res2 = client.get("https://tls.browserleaks.com/json")
```

**How to Override the Default Behavior:**

-   **To rotate through a specific list of identifiers**, pass a `list` of strings:
    ```python
    my_identifiers = ["chrome_120", "safari_16_0"]
    client = tls_requests.Client(client_identifier=my_identifiers)
    ```

-   **To use a single, static identifier**, pass a string:
    ```python
    client = tls_requests.Client(client_identifier="chrome_120")
    ```
-   **To disable rotation and use the library's single default identifier**, pass `None`:
    ```python
    client = tls_requests.Client(client_identifier=None)
    ```

* * *

### Proxy Rotator

Unlike headers and client identifiers, proxy rotation is **not enabled by default**, as the library cannot provide a list of free proxies. You must provide your own list to enable this feature.

To enable proxy rotation, pass a list of proxy strings to the `proxy` parameter. The library will automatically use a `weighted` strategy, prioritizing proxies that perform well.

```python
import tls_requests

proxy_list = [
    "http://user1:pass1@proxy.example.com:8080",
    "http://user2:pass2@proxy.example.com:8081",
    "socks5://proxy.example.com:8082",
    "proxy.example.com:8083",  #  (defaults to http)
    "http://user:pass@proxy.example.com:8084|1.0|US",  #  http://user:pass@host:port|weight|region
]

# Provide a list to enable proxy rotation.
with tls_requests.Client(proxy=proxy_list) as client:
    response = client.get("https://httpbin.org/get")
```

For more control, you can create a `ProxyRotator` instance with a specific strategy:

```python
from tls_requests.models.rotators import ProxyRotator

rotator = ProxyRotator.from_file(proxy_list, strategy="round_robin")

with tls_requests.Client(proxy=rotator) as client:
    response = client.get("https://httpbin.org/get")
```

> **Note:** The `Client` automatically provides performance feedback (success/failure, latency) to the `ProxyRotator`, making the `weighted` strategy highly effective.

* * *

### Asynchronous Support

All rotator features, including the smart defaults, work identically with `AsyncClient`.

```python
import tls_requests
import asyncio

async def main():
    # This async client automatically uses default header and identifier rotation.
    async with tls_requests.AsyncClient(
            headers=tls_requests.HeaderRotator(),
            client_identifier=tls_requests.TLSIdentifierRotator()
    ) as client:
        tasks = [client.get("https://httpbin.org/get") for _ in range(2)]
        responses = await asyncio.gather(*tasks)

        for i, r in enumerate(responses):
            print(f"Async Request {i+1} status: {r.status_code}")

asyncio.run(main())
```
