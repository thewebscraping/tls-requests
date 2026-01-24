# TLS Requests

[![GitHub License](https://img.shields.io/github/license/thewebscraping/tls-requests)](https://github.com/thewebscraping/tls-requests/blob/main/LICENSE)
[![CI](https://github.com/thewebscraping/tls-requests/actions/workflows/ci.yml/badge.svg)](https://github.com/thewebscraping/tls-requests/actions/workflows/ci.yml)
[![PyPI - Version](https://img.shields.io/pypi/v/wrapper-tls-requests)](https://pypi.org/project/wrapper-tls-requests/)
[![Sponsor](https://img.shields.io/badge/Sponsor-thewebscraping-pink?logo=github-sponsors&logoColor=white)](https://github.com/sponsors/thewebscraping)
![Python Version](https://img.shields.io/badge/Python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12-blue?style=flat)
![Pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white)

[![](https://img.shields.io/badge/Pytest-Linux%20%7C%20MacOS%20%7C%20Windows-blue?style=flat&logo=pytest&logoColor=white)](https://github.com/thewebscraping/tls-requests)
[![Documentation](https://img.shields.io/badge/Mkdocs-Documentation-blue?style=flat&logo=MaterialForMkDocs&logoColor=white)](https://thewebscraping.github.io/tls-requests/)

TLS Requests is a powerful Python library for secure HTTP requests, offering browser-like TLS client, fingerprinting, anti-bot page bypass, and high performance.

* * *

**Installation**
----------------

To install the library, you can choose between two methods:

#### **1\. Install via PyPI:**

```shell
pip install wrapper-tls-requests
```

#### **2\. Install via GitHub Repository:**

```shell
pip install git+https://github.com/thewebscraping/tls-requests.git
```

**Quick Start**
---------------

Start using TLS Requests with just a few lines of code. It automatically synchronizes headers based on your chosen browser identifier:

```python
import tls_requests
# The library automatically injects matching User-Agent and Sec-CH-UA headers
r = tls_requests.get("https://httpbin.org/headers", client_identifier="chrome_133")
r.json()["headers"]["User-Agent"]
'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36'
```

Basic automatically rotates for proxies and TLS identifiers:

```python
import tls_requests
proxy_rotator = tls_requests.ProxyRotator([
    "http://user1:pass1@proxy.example.com:8080",
    "http://user2:pass2@proxy.example.com:8081",
    "socks5://proxy.example.com:8082",
    "proxy.example.com:8083",  # defaults to http
    "http://user:pass@proxy.example.com:8084|1.0|US",  # weight and region support
])
r = tls_requests.get(
    "https://httpbin.org/get",
    proxy=proxy_rotator,
    client_identifier=tls_requests.TLSIdentifierRotator()
)
r
<Response [200 OK]>
r.status_code
200
```

**Introduction**
----------------

**TLS Requests** is a cutting-edge HTTP client for Python, offering a feature-rich,
highly configurable alternative to the popular [`requests`](https://github.com/psf/requests) library.

Built on top of [`tls-client`](https://github.com/bogdanfinn/tls-client),
it combines ease of use with advanced functionality for secure networking.

**Acknowledgment**: A big thank you to all contributors for their support!

### **Key Benefits**

*   **Bypass TLS Fingerprinting:** Mimic browser-like behaviors to navigate sophisticated anti-bot systems.
*   **Customizable TLS Client:** Select specific TLS fingerprints to meet your needs.
*   **Ideal for Developers:** Build scrapers, API clients, or other custom networking tools effortlessly.


**Why Use TLS Requests?**
-------------------------

Modern websites increasingly use **TLS Fingerprinting** and anti-bot tools like Cloudflare Bot Fight Mode to block web crawlers.

**TLS Requests** bypass these obstacles by mimicking browser-like TLS behaviors,
making it easy to scrape data or interact with websites that use sophisticated anti-bot measures.

### Unlocking Cloudflare Bot Fight Mode
![coingecko.png](https://raw.githubusercontent.com/thewebscraping/tls-requests/refs/heads/main/docs/static/coingecko.png)

**Example Code:**

```python
import tls_requests
r = tls_requests.get('https://www.coingecko.com/')
r
<Response [200]>
```

**Key Features**
----------------

### **Enhanced Capabilities**

*   **Browser-like TLS Fingerprinting**: Enables secure and reliable browser-mimicking connections.
*   **Dynamic Header Synchronization**: Automatically extracts browser versions from `client_identifier` and injects them into `User-Agent` and `sec-ch-ua` headers.
*   **High-Performance Backend**: Built on a Go-based HTTP backend with **Protocol Racing** (Happy Eyeballs) enabled by default for faster connections.
*   **Synchronous & Asynchronous Support**: Seamlessly switch between synchronous and asynchronous requests.
*   **Protocol Support**: Fully compatible with HTTP/1.1, HTTP/2, and HTTP/3 (Alpha).
*   **Strict Timeouts**: Reliable timeout management for precise control over request durations.

### **Additional Features**

*   **Internationalized Domain & URL Support**: Handles non-ASCII URLs effortlessly.
*   **Cookie Management**: Ensures session-based cookie persistence.
*   **Authentication**: Native support for Basic and Function authentication.
*   **Content Decoding**: Automatic handling of gzip and brotli-encoded responses.
*   **Hooks**: Perfect for logging, monitoring, tracing, or pre/post-processing requests and responses.
*   **Unicode Support**: Effortlessly process Unicode response bodies.
*   **Advanced TLS Options**: Support for `protocol_racing`, `allow_http` and `stream_id`.
*   **File Uploads**: Simplified multipart file upload support.
*   **Proxy Configuration**: Supports Socks5, HTTP, and HTTPS proxies for enhanced privacy.


**Documentation**
-----------------

Explore the full capabilities of TLS Requests in the documentation:

*   **[Quickstart Guide](https://thewebscraping.github.io/tls-requests/quickstart/)**: A beginner-friendly guide.
*   **[Advanced Topics](https://thewebscraping.github.io/tls-requests/advanced/client/)**: Learn to leverage specialized features.
*   **[Async Support](https://thewebscraping.github.io/tls-requests/advanced/async_client/)**: Handle high-concurrency scenarios.
*   **Custom TLS Configurations**:
    *   **[Wrapper TLS Client](https://thewebscraping.github.io/tls-requests/tls/)**
    *   **[TLS Client Profiles](https://thewebscraping.github.io/tls-requests/tls/profiles/)**
    *   **[Custom TLS Configurations](https://thewebscraping.github.io/tls-requests/tls/configuration/)**


Read the documentation: [**thewebscraping.github.io/tls-requests/**](https://thewebscraping.github.io/tls-requests/)

**Report Issues**
-----------------

Found a bug? Please [open an issue](https://github.com/thewebscraping/tls-requests/issues/).

By reporting an issue you help improve the project.

**Credits**
-----------------

Special thanks to [bogdanfinn](https://github.com/bogdanfinn/) for creating the awesome [tls-client](https://github.com/bogdanfinn/tls-client).
