import argparse
import sys
import logging

# hack to import from ipapocket
sys.path.append(".")

from ipapocket.network.krb5 import Krb5Client
from ipapocket.krb5.operations import as_req_wihtout_pa
from ipapocket.krb5.asn1 import *
from ipapocket.krb5.constants import ErrorCodes
from ipapocket.utils import logger


class UserEnum:
    def __init__(self, usernames: list, domain: str, ipa_host: str):
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
            as_req = as_req_wihtout_pa(self._domain, username)
            data = self._krb5_client.sendrcv(as_req.to_asn1().dump())
            # convert to response type
            krb_msg = KerberosResponseAsn1.load(data)
            if krb_msg.name != "KRB-ERROR":
                # client doesn't need preauth, so we get TGT right now
                # TODO
                self.printer(username, "without preauth")
            else:
                # if we need password (and user is active)
                if (
                    krb_msg.native["error-code"]
                    == ErrorCodes.KDC_ERR_PREAUTH_REQUIRED.value
                ):
                    self.printer(username, "need password")
                # if user's password is disabled or account locked out in LDAP (krb will not help with determine)
                if krb_msg.native["error-code"] == ErrorCodes.KDC_ERR_KEY_EXPIRED.value:
                    self.printer(
                        username, "password expired or client disabled in LDAP"
                    )
                # if user is locked out, but password has not been expired
                if (
                    krb_msg.native["error-code"]
                    == ErrorCodes.KDC_ERR_CLIENT_REVOKED.value
                ):
                    self.printer(username, "client locked out")


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
