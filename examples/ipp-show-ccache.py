#!/usr/bin/env python

from ipapocket.utils import logger
from ipapocket.krb5.ccache import Ccache
import argparse
import os
import logging


class ShowCcache:
    _content: bytes = None
    _ccache: Ccache = None

    def _read_file(self, path) -> bytes:
        with open(path, "rb") as f:
            self._content = f.read()

    def __init__(self, path):
        """
        Read CCACHE file in such order:
        1. KRB5CCNAME
        2. Supplied path
        """
        env_path = os.getenv("KRB5CCNAME")
        if (env_path is not None and env_path != "") and (path is None or path == ""):
            logging.debug(
                "Attempt to read file from path in KRB5CCNAME env ({})".format(env_path)
            )
            self._read_file(env_path)
        elif path is not None and path != "":
            logging.debug("Attempt to reaf file from supplied path ({})".format(path))
            self._read_file(path)
        else:
            raise AttributeError("Specify KRB5CCNAME or directly path")

        # attempt to parse ccache
        self._ccache = Ccache.from_bytes(self._content)

    def show(self):
        self._ccache.pprint()


if __name__ == "__main__":
    logger.init()
    parser = argparse.ArgumentParser(
        add_help=True, description="Show details from CCACHE file"
    )
    parser.add_argument(
        "-v",
        "--verbose",
        required=False,
        action="store_true",
        help="Verbose mode",
    )
    parser.add_argument(
        "--ccache",
        required=False,
        action="store",
        help="Path for CCACHE file to store TGT (will try KRB5CCNAME before)",
    )

    options = parser.parse_args()

    if options.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    sc = ShowCcache(options.ccache)
    sc.show()
