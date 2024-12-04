## Auto Download

This approach simplifies usage as it automatically detects your OS and downloads the appropriate version of the library. To use it:

#### Reference: [GitHub Releases - TLS Client](https://github.com/bogdanfinn/tls-client/releases/)


```pycon
>>> import tls_requests
>>> r = tls_requests.get('https://httpbin.org/get')
```

!!! note:
    The library takes care of downloading necessary files and stores them in the `tls_requests/bin` directory.

## Manual Download

If you want more control, such as selecting a specific version of the library, you can use the manual method:

```pycon
>>> from tls_requests.models.libraries import TLSLibrary
>>> TLSLibrary.download('1.7.10')
```

This method is useful if you need to ensure compatibility with specific library versions.

### Notes

1.  **Dependencies**: Ensure Python is installed and configured correctly in your environment.
2.  **Custom Directory**: If needed, the library’s downloaded binaries can be relocated manually to suit specific project structures.
3.  **Reference**: [TLS Client GitHub Releases](https://github.com/bogdanfinn/tls-client/releases/) provides details about available versions and updates.
