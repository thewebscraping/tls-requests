# Client Usage

The `Client` class is the primary interface for making synchronous HTTP requests with `tls_requests`. It manages persistent sessions, handles cookie storage, and allows for shared configuration across multiple requests.

If you are familiar with the `requests` library, `tls_requests.Client` is equivalent to `requests.Session`.

* * *

## Why Use the Client?

While you can use top-level functions like `tls_requests.get()`, using a `Client` is recommended for most applications because:

*   **Performance**: Reuses underlying TLS sessions and network connections.
*   **State Management**: Automatically manages cookies and authentication across multiple requests.
*   **Consistency**: Shared headers, proxies, and timeouts are applied to every request made with the client.

* * *

## Usage Patterns

### Recommended: Context Manager

Using the `with` statement ensures that the client is automatically closed and its native resources are freed once you are finished.

```python
import tls_requests

with tls_requests.Client() as client:
    response = client.get("https://httpbin.org/get")
    print(response.status_code)
```

### Manual Management

If you cannot use a context manager, ensure you call `.close()` manually.

```python
import tls_requests

client = tls_requests.Client()
response = client.get("https://httpbin.org/get")
# ... do more work ...
client.close()
```

* * *

## Persistent Configuration

You can set default values during client initialization that will apply to every subsequent request.

```python
import tls_requests

# Set global headers and a proxy
client = tls_requests.Client(
    headers={"User-Agent": "MyCustomBrowser/1.0"},
    proxy="http://127.0.0.1:8080"
)

# This request will use the custom User-Agent and Proxy
response = client.get("https://httpbin.org/headers")
```

### Merging Headers and Cookies

If you provide headers or cookies both at the client level and in an individual request, they are merged. Request-level values will override client-level values if there is a conflict.

```python
with tls_requests.Client(headers={"X-Client": "A"}) as client:
    # This request has both 'X-Client: A' and 'X-Request: B'
    resp = client.get("https://httpbin.org/headers", headers={"X-Request": "B"})
```

* * *

## Request Methods

The client supports all standard HTTP methods:

- `client.get(url, **kwargs)`
- `client.post(url, data=..., json=..., **kwargs)`
- `client.put(url, **kwargs)`
- `client.patch(url, **kwargs)`
- `client.delete(url, **kwargs)`
- `client.head(url, **kwargs)`
- `client.options(url, **kwargs)`

For more advanced scenarios like custom authentication or request hooks, refer to the dedicated guides in the [Advanced](../advanced/authentication.md) section.

*   **Merging Headers and Cookies:**
    Request-level values will override client-level values if there is a conflict.

```python
client_headers = {'X-Auth': 'client'}
request_headers = {'X-Custom': 'request'}
with tls_requests.Client(headers=client_headers) as client:
    response = client.get("https://httpbin.org/get", headers=request_headers)
    print(response.request.headers['X-Auth'])  # 'client'
    print(response.request.headers['X-Custom'])  # 'request'
```

*   **Other parameters:** Request-level options take precedence.

```python
with tls_requests.Client(auth=('user', 'pass')) as client:
    response = client.get("https://httpbin.org/get", auth=('admin', 'adminpass'))
    # Authorization header would be encoded 'admin:adminpass'
```

* * *

## Advanced Request Handling

For more control, explicitly build and send `Request` instances:

```python
request = tls_requests.Request("GET", "https://httpbin.org/get")
with tls_requests.Client() as client:
    response = client.send(request)
    print(response)  # <Response [200 OK]>
```

To combine client- and request-level configurations:

```python
with tls_requests.Client(headers={"X-Client-ID": "ABC123"}) as client:
    request = client.build_request("GET", "https://httpbin.org/json")
    # request.headers["X-Client-ID"] is present, but you can modify it
    del request.headers["X-Client-ID"]
    response = client.send(request)
    print(response)
```

* * *

## File Uploads

Upload files with control over file name, content, and MIME type:

```python
files = {'upload-file': (None, 'text content', 'text/plain')}
response = tls_requests.post("https://httpbin.org/post", files=files)
print(response.json()['form']['upload-file'])  # 'text content'
```

For further details, refer to the library's documentation.
