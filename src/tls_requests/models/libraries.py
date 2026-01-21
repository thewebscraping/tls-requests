from __future__ import annotations

import ctypes
import glob
import json
import os
import platform
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field, fields
from pathlib import Path
from platform import machine
from typing import List, Optional, Tuple

from tls_requests.utils import get_logger

logger = get_logger("TLSLibrary")

__all__ = ("TLSLibrary",)

LATEST_VERSION_TAG_NAME = "v1.13.1"
BIN_DIR = os.path.join(Path(__file__).resolve(strict=True).parent.parent / "bin")
RELEASE_CONFIG_PATH = os.path.join(BIN_DIR, "release.json")
GITHUB_API_URL = "https://api.github.com/repos/bogdanfinn/tls-client/releases"
PLATFORM = sys.platform
IS_UBUNTU = False
ARCH_MAPPING = {
    "amd64": "amd64",
    "x86_64": "amd64",
    "x86": "386",
    "i686": "386",
    "i386": "386",
    "arm64": "arm64",
    "aarch64": "arm64",
    "armv5l": "arm-5",
    "armv6l": "arm-6",
    "armv7l": "arm-7",
    "ppc64le": "ppc64le",
    "riscv64": "riscv64",
    "s390x": "s390x",
}

FILE_EXT = ".unk"
MACHINE_RAW = machine().lower()
MACHINE = ARCH_MAPPING.get(MACHINE_RAW) or MACHINE_RAW
if PLATFORM == "linux":
    FILE_EXT = "so"
    try:
        if hasattr(platform, "freedesktop_os_release"):
            platform_data = platform.freedesktop_os_release()
            curr_system: Optional[str] = None
            if "ID" in platform_data:
                curr_system = platform_data["ID"]
            else:
                curr_system = platform_data.get("id")

            if curr_system and "ubuntu" in curr_system.lower():
                IS_UBUNTU = True
    except Exception:
        pass

elif PLATFORM in ("win32", "cygwin"):
    PLATFORM = "windows"
    FILE_EXT = "dll"
elif PLATFORM == "darwin":
    FILE_EXT = "dylib"

PATTERN_RE = re.compile(r"%s-%s.*%s" % (PLATFORM, MACHINE, FILE_EXT), re.I)
PATTERN_UBUNTU_RE = re.compile(r"%s-%s.*%s" % ("ubuntu", MACHINE, FILE_EXT), re.I)
TLS_LIBRARY_PATH = os.getenv("TLS_LIBRARY_PATH")


@dataclass
class BaseRelease:
    @classmethod
    def model_fields_set(cls) -> set:
        return {model_field.name for model_field in fields(cls)}

    @classmethod
    def from_kwargs(cls, **kwargs):
        model_fields_set = cls.model_fields_set()
        return cls(**{k: v for k, v in kwargs.items() if k in model_fields_set})  # noqa


@dataclass
class ReleaseAsset(BaseRelease):
    browser_download_url: str
    name: Optional[str] = None


@dataclass
class Release(BaseRelease):
    name: Optional[str] = None
    tag_name: Optional[str] = None
    assets: List[ReleaseAsset] = field(default_factory=list)

    @classmethod
    def from_kwargs(cls, **kwargs):
        model_fields_set = cls.model_fields_set()
        assets = kwargs.pop("assets", []) or []
        kwargs["assets"] = [ReleaseAsset.from_kwargs(**asset_kwargs) for asset_kwargs in assets]
        return cls(**{k: v for k, v in kwargs.items() if k in model_fields_set})


class TLSLibrary:
    """TLS Library

    A utility class for managing the TLS library, including discovery, validation,
    downloading, and loading. This class facilitates interaction with system-specific
    binaries, ensuring compatibility with the platform and machine architecture.

    Class Attributes:
        _PATH (str): The current path to the loaded TLS library.

    Methods:
        fetch_api(version: Optional[str] = None, retries: int = 3) -> Generator[str, None, None]:
            Fetches library download URLs from the GitHub API for the specified version.

        is_valid(fp: str) -> bool:
            Validates a file path against platform-specific patterns.

        find() -> str:
            Finds the first valid library binary in the binary directory.

        find_all() -> list[str]:
            Lists all library binaries in the binary directory.

        download(version: Optional[str] = None) -> str:
            Downloads the library binary for the specified version.

        set_path(fp: str):
            Sets the path to the currently loaded library.

        load() -> ctypes.CDLL:
            Loads the library, either from an existing path or by discovering and downloading it.
    """

    _PATH: Optional[str] = None
    _LIBRARY: Optional[ctypes.CDLL] = None

    @staticmethod
    def _parse_version(version_string: str) -> Tuple[int, ...]:
        """Converts a version string (e.g., "v1.11.2") to a comparable tuple (1, 11, 2)."""
        try:
            parts = str(version_string).lstrip("v").split(".")
            return tuple(map(int, parts))
        except (ValueError, AttributeError):
            return 0, 0, 0

    @staticmethod
    def _parse_version_from_filename(filename: str) -> Tuple[int, ...]:
        """Extracts and parses the version from a library filename."""
        match = re.search(r"v?(\d+\.\d+\.\d+)", Path(filename).name)
        if match:
            return TLSLibrary._parse_version(match.group(1))
        return 0, 0, 0

    @classmethod
    def cleanup_files(cls, keep_file: Optional[str] = None):
        """Removes all library files in the BIN_DIR except for the one to keep."""
        for file_path in cls.find_all():
            is_remove = True
            if keep_file and Path(file_path).name == Path(keep_file).name:
                is_remove = False

            if is_remove:
                try:
                    os.remove(file_path)
                    logger.info(f"Removed old library file: {file_path}")
                except OSError as e:
                    logger.error(f"Error removing old library file {file_path}: {e}")

    @classmethod
    def import_config(cls) -> Optional[dict]:
        """Loads release data from local disk."""
        if os.path.exists(RELEASE_CONFIG_PATH):
            try:
                with open(RELEASE_CONFIG_PATH, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Error loading local release config: {e}")
        return None

    @classmethod
    def export_config(cls, data: dict):
        """Saves release data to local disk."""
        try:
            os.makedirs(BIN_DIR, exist_ok=True)
            with open(RELEASE_CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)
            logger.info(f"Saved release config to {RELEASE_CONFIG_PATH}")
        except Exception as e:
            logger.error(f"Error saving local release config: {e}")

    @classmethod
    def fetch_api(cls, version: Optional[str] = None, retries: int = 3):
        def _process_data(data):
            releases_data = data if isinstance(data, list) else [data]

            releases = [Release.from_kwargs(**kwargs) for kwargs in releases_data]

            if version is not None:
                version_ = "v%s" % version if not str(version).startswith("v") else str(version)
                releases = [
                    release for release in releases if re.search(version_, release.name or release.tag_name, re.I)
                ]

            found_urls = False
            for release in releases:
                for asset in release.assets:
                    if asset.name:
                        if IS_UBUNTU and PATTERN_UBUNTU_RE.search(asset.name):
                            ubuntu_urls.append(asset.browser_download_url)
                            found_urls = True
                        if PATTERN_RE.search(asset.name):
                            asset_urls.append(asset.browser_download_url)
                            found_urls = True
            return found_urls

        asset_urls: List[str] = []
        ubuntu_urls: List[str] = []
        api_data = None

        for _ in range(retries):
            try:
                with urllib.request.urlopen(GITHUB_API_URL, timeout=10) as response:
                    if response.status == 200:
                        content = response.read().decode("utf-8")
                        api_data = json.loads(content)
                        # Save the first element (latest release) to local config
                        if isinstance(api_data, list) and api_data:
                            cls.export_config(api_data[0])
                        elif isinstance(api_data, dict):
                            cls.export_config(api_data)

                        if _process_data(api_data):
                            logger.info("Fetched release data from GitHub API.")
                            break
            except Exception as ex:
                logger.debug(f"GitHub API fetch failed (Attempt {_ + 1}): {ex}")

        if not asset_urls and not ubuntu_urls:
            local_data = cls.import_config()
            if local_data:
                _process_data(local_data)
                logger.info(f"Loaded release data from local config: {RELEASE_CONFIG_PATH}")
            else:
                # Last resort: construct a direct download URL based on naming patterns
                # This works if API is rate-limited and no local config exists
                v_tag = version or LATEST_VERSION_TAG_NAME
                if not v_tag.startswith("v"):
                    v_tag = f"v{v_tag}"

                # Mapping for Windows architecture naming convention in bogdanfinn/tls-client
                win_arch_map = {"amd64": "64", "386": "32"}

                target_arches = [MACHINE]
                if PLATFORM == "windows" and MACHINE in win_arch_map:
                    target_arches.insert(0, win_arch_map[MACHINE])

                # Generate a few potential candidates for the fallback URL
                platforms = [PLATFORM]
                if IS_UBUNTU:
                    platforms.insert(0, "ubuntu")

                for plat in platforms:
                    for arch in target_arches:
                        # Try with 'v' and without 'v' in filename as naming patterns vary
                        for v_str in [v_tag, v_tag.lstrip("v")]:
                            direct_filename = f"tls-client-{plat}-{arch}-{v_str}.{FILE_EXT}"
                            direct_url = (
                                f"https://github.com/bogdanfinn/tls-client/releases/download/{v_tag}/{direct_filename}"
                            )
                            asset_urls.append(direct_url)

                logger.info(f"Fallback: generated direct download URLs: {', '.join(asset_urls)}")

        for url in ubuntu_urls:
            yield url

        for url in asset_urls:
            yield url

    @classmethod
    def find(cls) -> Optional[str]:
        for fp in cls.find_all():
            if PATTERN_RE.search(fp):
                return fp
        return None

    @classmethod
    def find_all(cls) -> List[str]:
        return [src for src in glob.glob(os.path.join(BIN_DIR, r"*")) if src.lower().endswith(("so", "dll", "dylib"))]

    @classmethod
    def update(cls):
        """Forces a download of the latest library version."""
        logger.info(f"Updating TLS library to version {LATEST_VERSION_TAG_NAME}...")
        downloaded_fp = cls.download(version=LATEST_VERSION_TAG_NAME)
        if downloaded_fp:
            cls.cleanup_files(keep_file=downloaded_fp)
            logger.info("Update complete.")
            return downloaded_fp
        logger.error("Update failed.")
        return None

    upgrade = update

    @classmethod
    def download(cls, version: Optional[str] = None) -> Optional[str]:
        try:
            logger.info(
                "System Info - Platform: %s, Machine: %s, File Ext : %s."
                % (
                    PLATFORM,
                    "%s (Ubuntu)" % MACHINE if IS_UBUNTU else MACHINE,
                    FILE_EXT,
                )
            )
            download_url = None
            for url in cls.fetch_api(version):
                if not url:
                    continue

                download_url = url
                logger.info("Trying to download library from: %s" % download_url)

                try:
                    destination_name = download_url.split("/")[-1]
                    destination = os.path.join(BIN_DIR, destination_name)

                    # Use standard library's urllib to download the file
                    with urllib.request.urlopen(download_url, timeout=15) as response:
                        if response.status != 200:
                            logger.debug(f"Skipping {download_url}: HTTP {response.status}")
                            continue

                        os.makedirs(BIN_DIR, exist_ok=True)
                        total_size = int(response.headers.get("content-length", 0))
                        chunk_size = 8192  # 8KB

                        with open(destination, "wb") as file:
                            downloaded = 0
                            while True:
                                chunk = response.read(chunk_size)
                                if not chunk:
                                    break

                                file.write(chunk)
                                downloaded += len(chunk)

                                # Simple text-based progress bar
                                if total_size > 0:
                                    percent = (downloaded / total_size) * 100
                                    bar_length = 50
                                    filled_length = int(bar_length * downloaded // total_size)
                                    bar = "=" * filled_length + "-" * (bar_length - filled_length)
                                    sys.stdout.write(f"\rDownloading {destination_name}: [{bar}] {percent:.1f}%")
                                    sys.stdout.flush()

                        sys.stdout.write("\n")
                        return destination
                except (urllib.error.URLError, urllib.error.HTTPError) as ex:
                    logger.debug(f"Failed to download from {download_url}: {ex}")
                    continue

            logger.error("All download attempts failed.")

        except Exception as e:
            logger.error("An unexpected error occurred during download: %s" % e)
        return None

    @classmethod
    def set_path(cls, fp: str):
        cls._PATH = fp

    @classmethod
    def load(cls):
        """
        Loads the TLS library. It checks for the correct version, downloads it if
        the local version is outdated or missing, and then loads it into memory.
        """
        target_version = cls._parse_version(LATEST_VERSION_TAG_NAME)

        if cls._LIBRARY and cls._PATH:
            cached_version = cls._parse_version_from_filename(cls._PATH)
            if cached_version == target_version:
                return cls._LIBRARY

        def _load_library(fp_):
            try:
                lib = ctypes.cdll.LoadLibrary(fp_)
                cls.set_path(fp_)
                cls._LIBRARY = lib
                logger.info(f"Successfully loaded TLS library: {fp_}")
                return lib
            except Exception as ex:
                logger.error(f"Unable to load TLS library '{fp_}', details: {ex}")
                try:
                    os.remove(fp_)
                except (FileNotFoundError, PermissionError):
                    pass

        if TLS_LIBRARY_PATH:
            logger.info(f"Loading TLS library from environment variable: {TLS_LIBRARY_PATH}")
            return _load_library(TLS_LIBRARY_PATH)

        logger.debug(f"Required library version: {LATEST_VERSION_TAG_NAME}")
        local_files = cls.find_all()
        newest_local_version: tuple[int, ...] = (0, 0, 0)
        newest_local_file = None

        if local_files:
            for file_path in local_files:
                file_version = cls._parse_version_from_filename(file_path)
                if file_version > newest_local_version:
                    newest_local_version = file_version
                    newest_local_file = file_path
            logger.debug(
                f"Found newest local library: {newest_local_file} (version {'.'.join(map(str, newest_local_version))})"
            )
        else:
            logger.debug("No local library found.")

        if newest_local_version < target_version:
            if newest_local_file:
                logger.warning(
                    f"Local library is outdated (Found: {'.'.join(map(str, newest_local_version))}, "
                    f"Required: {LATEST_VERSION_TAG_NAME}). "
                    f"Auto-downloading... To manually upgrade, run: `python -m tls_requests.models.libraries`"
                )
            else:
                logger.info(f"Downloading required library version {LATEST_VERSION_TAG_NAME}...")

            downloaded_fp = cls.download(version=LATEST_VERSION_TAG_NAME)
            if downloaded_fp:
                cls.cleanup_files(keep_file=downloaded_fp)
                library = _load_library(downloaded_fp)
                if library:
                    return library

            logger.error(
                f"Failed to download the required TLS library {LATEST_VERSION_TAG_NAME}. "
                "Please check your connection or download it manually from GitHub."
            )
            raise OSError("Failed to download the required TLS library.")

        if newest_local_file:
            library = _load_library(newest_local_file)
            if library:
                cls.cleanup_files(keep_file=newest_local_file)
                return library

        raise OSError("Could not find or load a compatible TLS library.")


if __name__ == "__main__":
    try:
        TLSLibrary.load()
    except Exception as ex:
        logger.error(f"Manual load test failed: {ex}")
