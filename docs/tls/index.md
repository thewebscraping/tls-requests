TLS-Client Documentation
========================

**Acknowledgment**

Special thanks to [`bogdanfinn`](https://github.com/bogdanfinn/tls-client). For more details, visit the [GitHub repository](https://github.com/bogdanfinn/tls-client) or explore the [documentation](https://bogdanfinn.gitbook.io/open-source-oasis).

## Wrapper TLS Client

The `TLSClient` class is a utility for managing and interacting with TLS sessions using a native library. It provides methods to handle cookies, sessions, and make HTTP requests with advanced TLS configurations.

The TLSClient class is designed to be used as a singleton-like interface. Upon first instantiation, the class initializes the underlying native TLS library and sets up method bindings.

```pycon
>>> from tls_requests import TLSClient
>>> TLSClient.initialize()
```

!!! note
    The first time you initialize the TLSClient class, it will automatically find and load the appropriate library for your machine.

### Methods

* * *
#### `setup()`

Initializes the native TLS library and binds its functions to the class methods.

*   **Purpose**: Sets up the library functions and their argument/return types for use in other methods.
*   **Usage**: This is automatically called when the class is first instantiated.

```pycon
>>> from tls_requests import TLSClient
>>> client = TLSClient.initialize()
```

* * *

#### `get_cookies(session_id: TLSSessionId, url: str) -> dict`

Retrieves cookies associated with a session for a specific URL.

*   **Parameters**:
    *   `session_id` (_TLSSessionId_): The identifier for the TLS session.
    *   `url` (_str_): The URL for which cookies are requested.
*   **Returns**: A dictionary of cookies.

```pycon
>>> from tls_requests import TLSClient
>>> TLSClient.initialize()
>>> cookies = TLSClient.get_cookies(session_id="session123", url="https://example.com")
```

* * *

#### `add_cookies(session_id: TLSSessionId, payload: dict)`

Adds cookies to a specific TLS session.

*   **Parameters**:
    *   `session_id` (_TLSSessionId_): The identifier for the TLS session.
    *   `payload` (_dict_): A dictionary containing cookies to be added.
*   **Returns**: The response object from the library.

```pycon
>>> from tls_requests import TLSClient
>>> TLSClient.initialize()
>>> payload = {
    "cookies": [{
        "_name": "foo2",
        "value": "bar2",
    },{
        "_name": "bar2",
        "value": "baz2",
    }],
    "sessionId": "session123",
    "url": "https://example.com",
}
>>> TLSClient.add_cookies(session_id="session123", payload=payload)
```

* * *

#### `destroy_all() -> bool`

Destroys all active TLS sessions.

*   **Returns**: `True` if all sessions were successfully destroyed, otherwise `False`.

```pycon
>>> from tls_requests import TLSClient
>>> TLSClient.initialize()
>>> success = TLSClient.destroy_all()
```

* * *
#### `destroy_session(session_id: TLSSessionId) -> bool`

Destroys a specific TLS session.

*   **Parameters**:
    *   `session_id` (_TLSSessionId_): The identifier for the session to be destroyed.
*   **Returns**: `True` if the session was successfully destroyed, otherwise `False`.

```pycon
>>> from tls_requests import TLSClient
>>> TLSClient.initialize()
success = TLSClient.destroy_session(session_id="session123")
```


* * *

#### `free_memory(response_id: TLSSessionId)`

Frees memory associated with a specific response.

*   **Parameters**:
    *   `response_id` (_str_): The identifier for the response to be freed.
*   **Returns**: None.

```pycon
>>> from tls_requests import TLSClient
>>> TLSClient.initialize()
>>> TLSClient.free_memory(response_id="response123")
```

* * *

#### `request(payload: dict)`

Sends a request using the TLS library. Using [TLSConfig](configuration) to generate payload.

*   **Parameters**:
    *   `payload` (_dict_): A dictionary containing the request payload (e.g., method, headers, body, etc.).
*   **Returns**: The response object from the library.

```pycon
>>> from tls_requests import TLSClient, TLSConfig
>>> TLSClient.initialize()
>>> config = TLSConfig(requestMethod="GET", requestUrl="https://example.com")
>>> response = TLSClient.request(config.to_dict())
```

* * *

#### `response(raw: bytes) -> TLSResponse`

Parses a raw byte response and frees associated memory.

*   **Parameters**:
    *   `raw` (_bytes_): The raw byte response from the TLS library.
*   **Returns**: A `TLSResponse` object.

```pycon
>>> from tls_requests import TLSClient
>>> TLSClient.initialize()
>>> parsed_response = TLSClient.response(raw_bytes)
```
