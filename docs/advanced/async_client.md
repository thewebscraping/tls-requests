# Asynchronous Support

`tls_requests` provides full support for asynchronous HTTP requests via the `AsyncClient`. This is essential for high-concurrency workloads, long-lived connections, and integration with modern async frameworks like FastAPI.

* * *

## Why Use Async?

*   **Concurrency**: efficient handling of many simultaneous requests without the overhead of threads.
*   **Performance**: Improved I/O throughput in data-intensive applications.
*   **Compatibility**: Seamless integration with the Python `asyncio` ecosystem.

* * *

## Making Async Requests

To send asynchronous requests, use the `AsyncClient` within an `async` function.

### Basic Example

```python
import asyncio
import tls_requests

async def main():
    async with tls_requests.AsyncClient() as client:
        response = await client.get("https://httpbin.org/get")
        print(f"Status: {response.status_code}")
        print(f"Data: {response.json()}")

if __name__ == "__main__":
    asyncio.run(main())
```

* * *

## Concurrent Requests

You can use `asyncio.gather` to execute multiple requests in parallel efficiently.

```python
import asyncio
import tls_requests

async def fetch_url(client, url):
    response = await client.get(url)
    return response.status_code

async def main():
    urls = [
        "https://httpbin.org/get",
        "https://httpbin.org/ip",
        "https://httpbin.org/user-agent"
    ]

    async with tls_requests.AsyncClient() as client:
        tasks = [fetch_url(client, url) for url in urls]
        results = await asyncio.gather(*tasks)
        print(f"Results: {results}")

asyncio.run(main())
```

* * *

## Key Differences from Sync Client

The `AsyncClient` mirrors the `Client` API but requires the `await` keyword for all network operations.

### Async Methods
All request methods are coroutines:

- `await client.get(url, ...)`
- `await client.post(url, ...)`
- `await client.put(url, ...)`
- `await client.patch(url, ...)`
- `await client.delete(url, ...)`
- `await client.request(method, url, ...)`

### Lifecycle Management
Always use the `async with` context manager to ensure that the underlying TLS sessions are automatically closed and resources are freed.

```python
async with tls_requests.AsyncClient() as client:
    # do work
    ...
# session is closed here
```
```

#### Manual Closing

Alternatively, explicitly close the client:

```python
import asyncio

async def fetch(url):
    client = tls_requests.AsyncClient()
    try:
        response = await client.get("https://httpbin.org/get")
    finally:
        await client.aclose()
```

* * *

By using `AsyncClient`, you can unlock the full potential of asynchronous programming in Python while enjoying the simplicity and power of TLS Requests.
