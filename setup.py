import glob
import os
from setuptools import setup

VERSION = '0.1'

def read(fname):
    return open(fname).read()

with open("requirements.txt") as f:
    requirements = f.read().splitlines()

setup(
    name='ipapocket',
    version = VERSION,
    description="Toolset for interaction with FreeIPA",
    long_description=read("README.md"),
    long_description_content_type="text/markdown",
    url = "https://github.com/c2micro/ipapocket",
    author = "c2micro",
    maintainer="c2micro",
    platforms=["Unix"],
    packages=['ipapocket', 'ipapocket.exceptions', 'ipapocket.krb5', 'ipapocket.krb5.types', 'ipapocket.krb5.crypto', 'ipapocket.network', 'ipapocket.utils'],
    scripts=glob.glob(os.path.join('examples', '*.py')),
    install_requires=requirements,
    classifiers=[
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.10",
    ]
)
