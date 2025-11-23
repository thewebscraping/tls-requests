import itertools
import json
from collections import Counter
from pathlib import Path

import pytest

from tls_requests.models.headers import Headers
from tls_requests.models.rotators import (HeaderRotator, ProxyRotator,
                                          TLSIdentifierRotator)
from tls_requests.models.urls import Proxy


@pytest.fixture
def proxy_list_fixture():
    return ["proxy1:8000", "proxy2:8000", "proxy3:8000"]


@pytest.fixture
def proxy_txt_file_fixture(tmp_path: Path):
    content = """
    # This is a comment, should be skipped
    proxy1:8000
    proxy2:8000

    proxy3:8000|2.5|us-east # proxy with weight and region
    """
    file_path = tmp_path / "proxies.txt"
    file_path.write_text(content)
    return file_path


@pytest.fixture
def proxy_json_file_fixture(tmp_path: Path):
    data = [
        {"url": "http://proxy1:8000", "weight": 1.0, "region": "eu"},
        {"url": "http://proxy2:8000", "weight": 3.0, "region": "us"},
    ]
    file_path = tmp_path / "proxies.json"
    file_path.write_text(json.dumps(data))
    return file_path


@pytest.fixture
def header_list_fixture():
    return [
        {
            "Accept": "application/json",
            "User-Agent": "Test-UA-1",
        },
        {
            "Accept": "text/html",
            "User-Agent": "Test-UA-2",
        },
    ]


class TestBaseRotator:
    def test_initialization(self, proxy_list_fixture):
        rotator = ProxyRotator(items=[Proxy(p) for p in proxy_list_fixture])
        assert len(rotator) == 3
        assert isinstance(rotator.items[0], Proxy)

    def test_from_file_list(self, proxy_list_fixture):
        rotator = ProxyRotator.from_file(proxy_list_fixture)
        assert len(rotator) == 3
        assert rotator.items[0].url == "http://proxy1:8000"

    def test_from_file_txt(self, proxy_txt_file_fixture):
        rotator = ProxyRotator.from_file(proxy_txt_file_fixture)
        assert len(rotator) == 3, "Blank lines and comments should be ignored."
        assert rotator.items[2].weight == 2.5
        assert rotator.items[2].region == "us-east"

    def test_from_file_json(self, proxy_json_file_fixture):
        rotator = ProxyRotator.from_file(proxy_json_file_fixture)
        assert len(rotator) == 2
        assert rotator.items[1].url == "http://proxy2:8000"
        assert rotator.items[1].weight == 3.0

    def test_from_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            ProxyRotator.from_file("non_existent_file.txt")

    def test_empty_rotator_raises_error(self):
        rotator = ProxyRotator.from_file([])
        with pytest.raises(ValueError, match="Rotator is empty"):
            rotator.next()

    @pytest.mark.asyncio
    async def test_async_empty_rotator_raises_error(self):
        rotator = ProxyRotator.from_file([])
        with pytest.raises(ValueError, match="Rotator is empty"):
            await rotator.anext()

    def test_add_remove(self):
        rotator = TLSIdentifierRotator.from_file(["chrome_120"])
        assert len(rotator) == 1
        rotator.add("firefox_120")
        assert len(rotator) == 2
        assert "firefox_120" in rotator.items
        rotator.remove("chrome_120")
        assert len(rotator) == 1
        assert "chrome_120" not in rotator.items

    @pytest.mark.asyncio
    async def test_async_add_remove(self):
        rotator = TLSIdentifierRotator.from_file(["chrome_120"])
        assert len(rotator) == 1
        await rotator.aadd("firefox_120")
        assert len(rotator) == 2
        assert "firefox_120" in rotator.items
        await rotator.aremove("chrome_120")
        assert len(rotator) == 1
        assert "chrome_120" not in rotator.items

    def test_default_strategy_is_random(self, proxy_list_fixture):
        """
        Tests that the default strategy is 'random' when none is specified.
        This is crucial for stateless shortcut API usage like `tls_requests.get()`.
        """
        # Initialize the rotator without specifying a `strategy`
        rotator = ProxyRotator.from_file(proxy_list_fixture)
        assert rotator.strategy == "random"

        # Check behavior: the results should not be a predictable round-robin sequence.
        # With 10 iterations, the probability of a random choice perfectly
        # matching a round-robin sequence is extremely low.
        results = [rotator.next() for _ in range(10)]

        # Generate the expected round-robin sequence for comparison
        round_robin_cycle = itertools.cycle(rotator.items)
        expected_round_robin_results = [next(round_robin_cycle) for _ in range(10)]

        assert results != expected_round_robin_results, \
            "Default strategy produced a predictable round-robin sequence."


class TestRotationStrategies:
    @pytest.mark.parametrize("strategy", ["round_robin", "random", "weighted"])
    def test_sync_strategies(self, strategy, proxy_list_fixture):
        proxies = [Proxy(p, weight=i + 1) for i, p in enumerate(proxy_list_fixture)]
        rotator = ProxyRotator(proxies, strategy=strategy)
        num_iterations = 100 if strategy == "weighted" else 10

        results = [rotator.next() for _ in range(num_iterations)]

        if strategy == "round_robin":
            assert results[0].url == "http://proxy1:8000"
            assert results[1].url == "http://proxy2:8000"
            assert results[2].url == "http://proxy3:8000"
            assert results[3].url == "http://proxy1:8000"

        elif strategy == "random":
            for res in results:
                assert res in proxies

        elif strategy == "weighted":
            counts = Counter(p.url for p in results)
            assert counts["http://proxy3:8000"] > counts["http://proxy1:8000"]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("strategy", ["round_robin", "random", "weighted"])
    async def test_async_strategies(self, strategy, proxy_list_fixture):
        proxies = [Proxy(p, weight=i + 1) for i, p in enumerate(proxy_list_fixture)]
        rotator = ProxyRotator(proxies, strategy=strategy)
        num_iterations = 100 if strategy == "weighted" else 10

        results = [await rotator.anext() for _ in range(num_iterations)]

        if strategy == "round_robin":
            assert results[0].url == "http://proxy1:8000"
            assert results[3].url == "http://proxy1:8000"

        elif strategy == "random":
            for res in results:
                assert res in proxies

        elif strategy == "weighted":
            counts = Counter(p.url for p in results)
            assert counts["http://proxy3:8000"] > counts["http://proxy1:8000"]


class TestProxyRotator:
    def test_mark_result_weighted(self):
        proxy = Proxy("proxy.example.com:8080", weight=2.0)
        rotator = ProxyRotator([proxy], strategy="weighted")

        initial_weight = proxy.weight
        rotator.mark_result(proxy, success=True)
        assert proxy.weight > initial_weight

        initial_weight = proxy.weight
        rotator.mark_result(proxy, success=False)
        assert proxy.weight < initial_weight

    @pytest.mark.asyncio
    async def test_async_mark_result_weighted(self):
        proxy = Proxy("proxy.example.com:8080", weight=2.0)
        rotator = ProxyRotator([proxy], strategy="weighted")

        initial_weight = proxy.weight
        await rotator.amark_result(proxy, success=True)
        assert proxy.weight > initial_weight

        initial_weight = proxy.weight
        await rotator.amark_result(proxy, success=False)
        assert proxy.weight < initial_weight


class TestHeaderRotator:
    def test_rebuild_item(self):
        item = HeaderRotator.rebuild_item({"User-Agent": "Test"})
        assert isinstance(item, Headers)
        assert item["user-agent"] == "Test"

    def test_next_with_user_agent_override(self, header_list_fixture):
        """
        Tests that overriding the User-Agent returns a modified COPY,
        and does NOT mutate the original header object in the rotator.
        This test is independent of the rotation strategy.
        """
        rotator = HeaderRotator.from_file(header_list_fixture)  # Uses default (random) strategy
        custom_ua = "My-Custom-Bot/1.0"

        # Get a header (randomly) and override its UA
        modified_header = rotator.next(user_agent=custom_ua)
        assert modified_header["User-Agent"] == custom_ua

        # Find the original header object in the rotator's list that corresponds
        # to the one we pulled (using the unique 'Accept' header from our fixture).
        original_header_in_list = next(
            h for h in rotator.items if h["Accept"] == modified_header["Accept"]
        )

        # The most important check: ensure the original object was NOT changed.
        assert original_header_in_list["User-Agent"] != custom_ua
        assert "Test-UA-" in original_header_in_list["User-Agent"]

        # Ensure it is a copy, not the same object.
        assert modified_header is not original_header_in_list

    @pytest.mark.asyncio
    async def test_anext_with_user_agent_override(self, header_list_fixture):
        """
        Tests the async version of the User-Agent override, ensuring the
        original object in the rotator remains unchanged.
        """
        rotator = HeaderRotator.from_file(header_list_fixture)  # Uses default (random) strategy
        custom_ua = "My-Custom-Bot/1.0"

        # Get a header (randomly) and override its UA
        modified_header = await rotator.anext(user_agent=custom_ua)
        assert modified_header["User-Agent"] == custom_ua

        # Find the original header object in the list
        original_header_in_list = next(
            h for h in rotator.items if h["Accept"] == modified_header["Accept"]
        )

        # Ensure the original object was NOT changed
        assert original_header_in_list["User-Agent"] != custom_ua
