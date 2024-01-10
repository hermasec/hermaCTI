#!/usr/bin/env python
from codecs import open
import os.path


from setuptools import find_packages, setup

setup(
    # ...
    entry_points={
        "medallion.backends": [
            "MyEPName = hermacti.with_backends:MyCustomBackend",
        ],
    }
)
