from __future__ import annotations

import asyncio

from tls_requests.models.request import Request


def test_request_properties():
    req = Request("GET", "http://ex.com")
    assert req.id == ""
    assert req.content == b""

    # repr
    assert "GET" in repr(req)
    assert "http://ex.com" in repr(req)


def test_request_aread():
    req = Request("POST", "http://ex.com", data={"a": 1})

    async def run():
        return await req.aread()

    res = asyncio.run(run())
    assert b"a=1" in res
