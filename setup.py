#!/usr/bin/env python

import os
import re
import sys
from codecs import open

from setuptools import setup

BASE_DIR = os.path.dirname(__file__)
CURRENT_PYTHON = sys.version_info[:2]
REQUIRED_PYTHON = (3, 8)

if CURRENT_PYTHON < REQUIRED_PYTHON:
    sys.stderr.write(
        """Python version not supported, you need to use Python version >= {}.{}""".format(
            *REQUIRED_PYTHON
        )
    )
    sys.exit(1)


def normalize(name) -> str:
    name = re.sub(r"\s+", "-", name)
    return re.sub(r"[-_.]+", "-", name).lower()


version = {}
with open(os.path.join(BASE_DIR, "tls_requests", "__version__.py"), "r", "utf-8") as f:
    exec(f.read(), version)

if __name__ == "__main__":
    setup(
        name=version["__title__"],
        version=version["__version__"],
        description=version["__description__"],
        long_description_content_type="text/markdown",
        author=version["__author__"],
        author_email=version["__author_email__"],
        url=version["__url__"],
    )
