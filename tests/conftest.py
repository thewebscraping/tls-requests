from __future__ import annotations

import tls_requests

pytest_plugins = ["pytest_httpserver", "pytest_asyncio"]


def pytest_configure(config):
    tls_requests.TLSLibrary.load()
