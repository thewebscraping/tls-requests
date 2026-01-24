# Event Hooks

`tls_requests` supports event hooks, enabling you to execute custom logic during specific events in the HTTP request/response lifecycle. These hooks are ideal for logging, monitoring, tracing, or pre/post-processing requests and responses.

* * *

## Hook Types

### 1. Request Hook

Executed after the request is fully prepared but before being sent to the network. It receives the `request` object as its only argument, allowing for inspection or final modifications.

### 2. Response Hook

Triggered after the response is received from the network but before being returned to the caller. It receives the `response` object, allowing for data processing or inspection.

* * *

## Using Hooks

Hooks are registered by providing a dictionary where keys are `'request'` or `'response'`, and values are lists of callable functions.

### Example: Logging Requests and Responses

```python
import tls_requests

def log_request(request):
    print(f"Request event: {request.method} {request.url}")

def log_response(response):
    print(f"Response event: {response.status_code} for {response.url}")

# Create a client with hooks
client = tls_requests.Client(hooks={
    'request': [log_request],
    'response': [log_response]
})
```

* * *

### Example: Automatic Error Handling

You can use hooks to automatically raise exceptions for specific status codes:

```python
import tls_requests

def raise_on_4xx_5xx(response):
    response.raise_for_status()

client = tls_requests.Client(hooks={'response': [raise_on_4xx_5xx]})
# Requests through this client will now raise errors automatically on failure
```

* * *

## Managing Hooks

### During Client Initialization

You can pass the `hooks` dictionary when creating a `Client` or `AsyncClient`:

```python
client = tls_requests.Client(hooks={
    'request': [log_request],
    'response': [log_response, raise_on_4xx_5xx],
})
```

### Dynamically Updating Hooks

You can update hooks after a client has been initialized using the `.hooks` property:

```python
client = tls_requests.Client()

# Add a request hook
client.hooks['request'] = [log_request]

# Add a response hook
client.hooks['response'] = [log_response]

# Completely replace hooks
client.hooks = {
    'request': [log_request],
    'response': [raise_on_4xx_5xx],
}
```

With event hooks, you can modularize cross-cutting concerns like authentication refreshes, telemetry, and detailed logging.
--------------

1.  **Access Content**: Use `.read()` or `await .aread()` in asynchronous contexts to access `response.content` before returning it.
2.  **Always Use Lists:** Hooks must be registered as **lists of callables**, even if you are adding only one function.
3.  **Combine Hooks:** You can register multiple hooks for the same event type to handle various concerns, such as logging and error handling.
4.  **Order Matters:** Hooks are executed in the order they are registered.

With hooks, TLS Requests provides a flexible mechanism to seamlessly integrate monitoring, logging, or custom behaviors into your HTTP workflows.
