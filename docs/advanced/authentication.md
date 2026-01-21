# Authentication

This section covers how to use authentication in your requests with `tls_requests`, offering both built-in options and the flexibility to define custom mechanisms.

* * *

## Basic Authentication

### Using a Tuple (Username and Password)

For basic HTTP authentication, pass a tuple `(username, password)` when initializing a `Client`. This will automatically include the credentials in the `Authorization` header for all outgoing requests:

```python
import tls_requests

client = tls_requests.Client(auth=("username", "secret"))
response = client.get("https://httpbin.org/basic-auth/username/secret")
```

* * *

### Using a Custom Function

To customize how authentication is handled, you can use a function that modifies the request directly:

```python
import tls_requests

def custom_auth(request):
    request.headers["X-Authorization"] = "123456"
    return request

response = tls_requests.get("https://httpbin.org/headers", auth=custom_auth)
print(response.request.headers["X-Authorization"])  # Outputs: 123456
```

* * *

## Custom Authentication

For advanced use cases, you can define custom authentication schemes by subclassing `tls_requests.Auth` and overriding the `build_auth` method.

### Bearer Token Authentication

This example demonstrates how to implement Bearer token-based authentication by adding an `Authorization` header:

```python
import tls_requests

class BearerAuth(tls_requests.Auth):
    def __init__(self, token):
        self.token = token

    def build_auth(self, request: tls_requests.Request) -> tls_requests.Request:
        request.headers["Authorization"] = f"Bearer {self.token}"
        return request
```

* * *

### Usage Example

To use your custom `BearerAuth` implementation:

```python
import tls_requests

# Define custom class as above
auth = BearerAuth(token="your_jwt_token")
response = tls_requests.get("https://httpbin.org/headers", auth=auth)

print(response.request.headers["Authorization"])  # Outputs: Bearer your_jwt_token
```

With these approaches, you can integrate various authentication strategies into your `tls_requests` workflow, whether built-in or custom-designed for specific needs.
