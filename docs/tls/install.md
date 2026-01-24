# Installing TLS Binaries

The `tls_requests` library requires a native binary (`.so`, `.dll`, or `.dylib`) to handle the underlying TLS fingerprinting. The library is designed to manage these binaries automatically.

* * *

## Automatic Management

This is the recommended approach. When you first use `tls_requests` to make a request, it will automatically detect your operating system and architecture, download the appropriate binary, and store it in the library's internal `bin/` directory.

```python
import tls_requests

# The first call will trigger the binary download if it doesn't exist
response = tls_requests.get('https://httpbin.org/get')
print(response.status_code)
```

!!! note
    The binaries are cached locally. Subsequent requests will reuse the existing binary without any network overhead.

* * *

## Manual Download

If your environment has restricted internet access or if you need a specific version of the underlying `tls-client` library, you can trigger a download manually.

```python
from tls_requests import TLSLibrary

# Download a specific version
TLSLibrary.download(version='1.13.1')
```

This ensures the binary is ready before your main application code begins execution.

* * *

## Advanced Configuration

### Custom Binary Path
You can override the automatic discovery by setting the `TLS_LIBRARY_PATH` environment variable to the absolute path of a compatible binary.

```bash
export TLS_LIBRARY_PATH=/path/to/your/custom/library.so
```

### Dependencies
- **Python**: 3.9 or higher.
- **Operating Systems**: Windows, macOS (Intel/Apple Silicon), and most Linux distributions (Ubuntu, Debian, CentOS, etc.).
- **Architecture**: x86_64 (amd64), ARM64, and others.

For more information on the available versions, refer to the [TLS Client GitHub Releases](https://github.com/bogdanfinn/tls-client/releases/).
