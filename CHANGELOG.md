Release History
================

1.2.3 (2026-01-24)
------------------
**Improvements:**

- **Enhanced IPv6 Support**: Implemented automatic repair for naked IPv6 addresses (e.g., `2001:db8::1` -> `[2001:db8::1]`) and strict bracket validation.
- **Robust URL Handling**: Added default `http://` scheme for schemeless URLs and improved component-based building logic to prevent crashes.
- **Type Safety**: Resolved Mypy strict type inconsistencies and added comprehensive test coverage for IPv6 edge cases.

**Bugfixes:**

- **Python 3.9 Compatibility**: Fixed `RuntimeError: There is no current event loop` during rotator initialization by implementing lazy asyncio lock loading.
- **Redirect Logic**: Fixed `Headers.__getitem__` to correctly raise `KeyError` for missing keys, ensuring compatibility with standard redirect handling.

1.2.2 (2026-01-21)
------------------
**Improvements:**

- **Standardized API Parameters**: Renamed `tls_identifier` to `client_identifier` and `tls_debug` to `debug` for better consistency and professional API surface.
- **Src Layout Migration**: Refactored the project structure to use a modern `src/` layout, improving package isolation and build reliability.
- **Type Safety & Testing**: Integrated `mypy` for strict type checking and migrated to `uv run pytest` for comprehensive test verification (80+ tests passing).
- **Backward Compatibility**: Implemented a centralized fallback and logging warning system for legacy parameters (planned removal in v1.3.0).
- **Modernized CI/CD**: Fully migrated from `Makefile` to `uv`. Optimized GitHub Actions matrix to support Python 3.9 through 3.13 across Linux, macOS, and Windows.
- **Enhanced Platform Support**: Improved detection and loading logic for ARM64/aarch64 architectures (Apple Silicon, AWS Graviton).
- **Project Sustainability**: Added GitHub Sponsors support to the repository metadata and documentation.

1.1.7 (2025-11-23)
------------------
**Improvements:**

- Optimized logging. ([#46](https://github.com/thewebscraping/tls-requests/issues/46))
- Fixed cookie response handling. ([#47](https://github.com/thewebscraping/tls-requests/issues/47))

1.1.6 (2025-10-14)
------------------
**Enhancements:**
This pull request introduces two major enhancements that significantly improve the library's anti‑detection capabilities and overall robustness:

**A Smart Rotator System**
- Automatically rotates proxies, headers, and TLS identifiers to mimic authentic traffic.
- Introduced three new rotator classes: `ProxyRotator`, `HeaderRotator`, and `TLSIdentifierRotator`.
- Client and AsyncClient now enable header and TLS identifier rotation by default, using built‑in realistic templates.
- Unified parameters accept a single value, a list, or a pre‑configured Rotator instance.
- Proxy feedback loop (`mark_result`/`amark_result`) optimizes weighted rotation strategy.

**Robust Library Management**
- Dependency‑free, self‑managing mechanism for the core `tls-client` C library lifecycle.
- Removed `requests` and `tqdm`; now uses built‑in `urllib` and [json](cci:1://file:///Users/twofarm/Desktop/works/tls_requests/tls_requests/models/response.py:204:4-205:43).
- TLSLibrary is version‑aware, automatically downloading the correct version from GitHub when needed.
- Automatic cleanup of old library files after successful updates.

1.0.7 (2024-12-14)
-------------------
**Bugfixes:**

- Fix URL.
- Fix Proxy.

1.0.6 (2024-12-12)
-------------------
**Bugfixes:**

- Fix request file (image file, etc).

1.0.5 (2024-12-11)
-------------------
**Bugfixes:**

- Fix mkdocs deploy.

1.0.4 (2024-12-11)
-------------------
**Improvements:**

- Add unit tests.
- Improve document.

**Bugfixes:**

- Fix timeout.
- Fix missing port redirection.


1.0.3 (2024-12-05)
-------------------
**Improvements**

- improve document.

**Bugfixes**

- Fix multipart encoders, cross share auth.

1.0.2 (2024-12-05)
-------------------
**Improvements**
- Download specific TLS library versions.
- Add a document.

1.0.1 (2024-12-04)
-------------------
- First release
