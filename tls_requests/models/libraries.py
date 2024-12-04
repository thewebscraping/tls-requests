import ctypes
import glob
import os
import re
from dataclasses import dataclass, field, fields
from pathlib import Path
from platform import machine
from sys import platform
from typing import Optional

import requests
from tqdm import tqdm

__all__ = ["TLSLibrary"]

BIN_DIR = os.path.join(Path(__file__).resolve(strict=True).parent.parent / "bin")
GITHUB_API_URL = "https://api.github.com/repos/bogdanfinn/tls-client/releases"
PATTERN_RE = re.compile(
    r"xgo[a-zA-Z0-9.-]+%s-%s\.(so|dll|dylib)" % (platform, machine()), re.I
)


@dataclass
class BaseRelease:

    @classmethod
    def model_fields_set(cls) -> set:
        return {model_field.name for model_field in fields(cls)}

    @classmethod
    def from_kwargs(cls, **kwargs):
        model_fields_set = cls.model_fields_set()
        return cls(**{k: v for k, v in kwargs.items() if k in model_fields_set})


@dataclass
class ReleaseAsset(BaseRelease):
    browser_download_url: str
    name: Optional[str] = None


@dataclass
class Release(BaseRelease):
    name: Optional[str] = None
    tag_name: Optional[str] = None
    assets: list[ReleaseAsset] = field(default_factory=list)

    @classmethod
    def from_kwargs(cls, **kwargs):
        model_fields_set = cls.model_fields_set()
        assets = kwargs.pop("assets", []) or []
        kwargs["assets"] = [
            ReleaseAsset.from_kwargs(**asset_kwargs) for asset_kwargs in assets
        ]
        return cls(**{k: v for k, v in kwargs.items() if k in model_fields_set})


class TLSLibrary:
    @classmethod
    def fetch_api(cls, version: str = None, retries: int = 3):
        for _ in range(retries):
            try:
                response = requests.get(GITHUB_API_URL)
                if response.ok:
                    response_json = response.json()
                    releases = [
                        Release.from_kwargs(**kwargs) for kwargs in response_json
                    ]
                    assets = [
                        asset
                        for release in releases
                        for asset in release.assets
                        if "xgo" in str(asset.browser_download_url)
                    ]
                    if version is not None:
                        for asset in assets:
                            if str(version) == asset.name:
                                return [asset.browser_download_url]

                    return [asset.browser_download_url for asset in assets]
            except Exception as e:
                print("Unable to fetch GitHub API: %s" % e)

        return []

    @classmethod
    def find(cls) -> str:
        for fp in cls.find_all():
            if PATTERN_RE.search(fp):
                return fp

    @classmethod
    def find_all(cls) -> list[str]:
        return glob.glob(os.path.join(BIN_DIR, r"*"))

    @classmethod
    def download(cls, version: str = None) -> str:
        try:
            download_url = None
            for download_url in cls.fetch_api(version):
                if PATTERN_RE.search(download_url):
                    break

            if download_url:
                destination = os.path.join(BIN_DIR, download_url.split("/")[-1])
                with requests.get(download_url, stream=True) as response:
                    response.raise_for_status()
                    os.makedirs(BIN_DIR, exist_ok=True)
                    total_size = int(response.headers.get("content-length", 0))
                    chunk_size = 1024
                    with open(
                        os.path.join(BIN_DIR, download_url.split("/")[-1]), "wb"
                    ) as file, tqdm(
                        desc=destination,
                        total=total_size,
                        unit="iB",
                        unit_scale=True,
                        unit_divisor=chunk_size,
                    ) as progress_bar:
                        for chunk in response.iter_content(chunk_size):
                            size = file.write(chunk)
                            progress_bar.update(size)

                return destination

        except requests.exceptions.HTTPError as e:
            print("Unable to download file: %s" % e)

    @classmethod
    def load(cls):
        path = cls.find() or cls.download()
        if not path:
            raise OSError("Your system does not support TLS Library.")

        try:
            library = ctypes.cdll.LoadLibrary(path)
            return library
        except OSError as e:
            try:
                os.remove(path)
            except FileNotFoundError:
                pass

            raise OSError("Unable to load TLS Library, details: %s" % e)
