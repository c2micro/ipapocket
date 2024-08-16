from ipapocket.utils import logger
from ipapocket.krb5.ccache import Ccache
import argparse
import os
import logging


class TicketRenew:
    _content: bytes = None
    _ccache: Ccache = None
    _ipa_host: str = None

    def _read_file(self, path) -> bytes:
        with open(path, "rb") as f:
            self._content = f.read()

    def __init__(self, path, ipa_host):
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
        self._ipa_host = ipa_host

    def renew(self):
        pass


if __name__ == "__main__":
    logger.init()
    parser = argparse.ArgumentParser(
        add_help=True, description="Renew existing ticket in CCACHE"
    )
    parser.add_argument(
        "-H",
        "--ipa-host",
        required=True,
        action="store",
        help="IP address or FQDN of FreeIPA KDC",
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
        help="Path for CCACHE file to store TGS (by default will take from KRB5CCNAME)",
    )

    options = parser.parse_args()

    tmp = TicketRenew(options.ccache, options.ipa_host)
    tmp.renew()
