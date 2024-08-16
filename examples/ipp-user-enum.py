#!/usr/bin/env python

import argparse
import sys
import logging

from ipapocket.network.krb5 import Krb5Client
from ipapocket.krb5.operations import BaseKrb5Operations
from ipapocket.krb5.constants import ErrorCodes
from ipapocket.utils import logger
from ipapocket.krb5.objects import KerberosResponse


class UserEnum:
    def __init__(self, usernames: list, domain: str, ipa_host: str):
        self._base = BaseKrb5Operations(domain)

        self._usernames = usernames
        self._domain = domain
        self._ipa_host = ipa_host
        self._krb5_client = Krb5Client(ipa_host)

    def printer(self, username: str, options: str):
        temp = username
        if options != "":
            temp += " (%s)" % options
        logging.info(temp)

    def enumerate(self):
        for username in self._usernames:
            logging.debug("try username: {}".format(username))
            as_req = self._base.as_req_without_pa(username)
            data = self._krb5_client.sendrcv(as_req.dump())
            # convert to response type
            response = KerberosResponse.load(data)
            if response.is_krb_error:
                rep = response.krb_error
                if rep.error_code == ErrorCodes.KDC_ERR_PREAUTH_REQUIRED:
                    self.printer(username, "need password")
                if rep.error_code == ErrorCodes.KDC_ERR_KEY_EXPIRED:
                    # we can't determine this via kerberos
                    self.printer(
                        username, "password expired or client disabled in LDAP"
                    )
                if rep.error_code == ErrorCodes.KDC_ERR_CLIENT_REVOKED:
                    self.printer(username, "client locked out")
            else:
                # client doesn't need preauth
                self.printer(username, "without preauth")
                pass


def main():
    """
    Example of usage:
    python3 ./examples/user_enum.py -U ~/users.list -d ipa.test -H ipa.test
    """
    logger.init()
    parser = argparse.ArgumentParser(
        add_help=True, description="Enumerate users and state via kerberos"
    )
    parser.add_argument(
        "-v", "--verbose", required=False, action="store_true", help="Verbose mode"
    )
    parser.add_argument(
        "-U",
        "--username-file",
        required=True,
        action="store",
        help="Path to file with usernames",
    )
    parser.add_argument(
        "-d",
        "--domain",
        required=True,
        action="store",
        help="Domain name, e.g. ipa.test",
    )
    parser.add_argument(
        "-H",
        "--ipa-host",
        required=True,
        action="store",
        help="IP address or FQDN of FreeIPA KDC",
    )

    options = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    if options.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    with open(options.username_file, "r") as f:
        logging.debug("read file with usernames")
        usernames = f.read().splitlines()

    user_enum = UserEnum(usernames, options.domain, options.ipa_host)
    user_enum.enumerate()


if __name__ == "__main__":
    main()
