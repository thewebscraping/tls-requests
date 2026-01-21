# TLS Client Internals

The `tls_requests` library is built as a wrapper around a high-performance native TLS implementation. While most users should interact with the `Client` or `AsyncClient` classes, this section documents the lower-level `TLSClient` interface.

**Acknowledgment**

This project utilizes the core logic from [`bogdanfinn/tls-client`](https://github.com/bogdanfinn/tls-client). We express our gratitude for their open-source contributions.

* * *

## The TLSClient Class

The `TLSClient` class manages interactions with the native TLS library. It handles session management, cookie persistence, and raw HTTP request dispatching.

The `TLSClient` functions as a singleton interface. Upon first use, it automatically locates and initializes the appropriate native binary for your operating system.

```python
from tls_requests import TLSClient

# Manual initialization (optional, usually automatic)
TLSClient.initialize()
```

* * *

## Methods

### `get_cookies(session_id: str, url: str) -> dict`

Retrieves cookies associated with a specific session and URL.

*   **Parameters**:
    *   `session_id`: The unique identifier for the TLS session.
    *   `url`: The URL for which cookies are requested.
*   **Returns**: A dictionary of cookies.

```python
from tls_requests import TLSClient

cookies = TLSClient.get_cookies(session_id="my-session-123", url="https://httpbin.org")
```

* * *

### `add_cookies(session_id: str, payload: dict)`

Injects cookies into a specific TLS session.

*   **Parameters**:
    *   `session_id`: The identifier for the session.
    *   `payload`: A dictionary containing cookie data and metadata.

```python
from tls_requests import TLSClient

payload = {
    "cookies": [
        {"name": "session_id", "value": "xyz123"},
        {"name": "theme", "value": "dark"}
    ],
    "sessionId": "my-session-123",
    "url": "https://httpbin.org/"
}
TLSClient.add_cookies(session_id="my-session-123", payload=payload)
```

* * *

### `destroy_all() -> bool`

Destroys all active TLS sessions and frees associated memory in the native library.

*   **Returns**: `True` if all sessions were successfully destroyed.

```python
from tls_requests import TLSClient

success = TLSClient.destroy_all()
```

* * *

### `destroy_session(session_id: str) -> bool`

Gracefully closes and removes a specific session.

*   **Parameters**:
    *   `session_id`: The ID of the session to terminate.
*   **Returns**: `True` if the session was successfully removed.

```python
from tls_requests import TLSClient

TLSClient.destroy_session(session_id="my-session-123")
```

*   **Parameters**:
    *   `session_id` (_TLSSessionId_): The identifier for the session to be destroyed.
*   **Returns**: `True` if the session was successfully destroyed, otherwise `False`.

```python
from tls_requests import TLSClient
TLSClient.initialize()
success = TLSClient.destroy_session(session_id="session123")
```


* * *

#### `free_memory(response_id: TLSSessionId)`

Frees memory associated with a specific response.

*   **Parameters**:
    *   `response_id` (_str_): The identifier for the response to be freed.
*   **Returns**: None.

```python
from tls_requests import TLSClient
TLSClient.initialize()
TLSClient.free_memory(response_id="response123")
```

* * *

#### `request(payload: dict)`

Sends a request using the TLS library. Using [TLSConfig](configuration) to generate payload.

*   **Parameters**:
    *   `payload` (_dict_): A dictionary containing the request payload (e.g., method, headers, body, etc.).
*   **Returns**: The response object from the library.

```python
from tls_requests import TLSClient, TLSConfig
TLSClient.initialize()
config = TLSConfig(requestMethod="GET", requestUrl="https://httpbin.org/get")
response = TLSClient.request(config.to_dict())
```

* * *

#### `response(raw: bytes) -> TLSResponse`

Parses a raw byte response and frees associated memory.

*   **Parameters**:
    *   `raw` (_bytes_): The raw byte response from the TLS library.
*   **Returns**: A `TLSResponse` object.

```python
from tls_requests import TLSClient
TLSClient.initialize()
parsed_response = TLSClient.response(raw_bytes)
```
