import glob
import os
from setuptools import setup

VERSION = '0.1'

def read(fname):
    return open(fname).read()

requirements="""\
annotated-types==0.7.0
asn1crypto==1.5.1
bitarray==2.9.2
pycryptodomex==3.20.0
setuptools==72.2.0
typing_extensions==4.12.2
pyparsing==3.1.2
"""

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
