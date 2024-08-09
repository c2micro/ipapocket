import argparse
import sys

# hack to import from ipapocket
sys.path.append(".")

from ipapocket.network.krb5 import Krb5Client
from ipapocket.krb5.operations import (
    as_req_wihtout_pa,
    as_req_with_pa,
    get_preferred_etypes,
)
from ipapocket.krb5.asn1 import *
from ipapocket.krb5.constants import ErrorCodes
from ipapocket.exceptions.exceptions import UnexpectedKerberosError


class GetTgt:
    def __init__(self, username, password, domain, ipa_host):
        self._username = username
        self._password = password
        self._domain = domain
        self._ipa_host = ipa_host
        self._krb5_client = Krb5Client(ipa_host)

    def getTgt(self):
        as_req = as_req_wihtout_pa(self._domain, self._username)
        data = self._krb5_client.sendrcv(as_req.to_asn1().dump())
        # convert to response type
        krb_msg = KerberosResponseAsn1.load(data)
        if krb_msg.name != "KRB-ERROR":
            # client doesn't need preauth, so we get TGT right now
            # TODO
            pass
        else:
            if (
                krb_msg.native["error-code"]
                != ErrorCodes.KDC_ERR_PREAUTH_REQUIRED.value
            ):
                raise UnexpectedKerberosError(krb_msg)
            else:
                # get preferred etypes + salt
                etype = get_preferred_etypes(krb_msg)
                as_req = as_req_with_pa(
                    self._domain, self._username, self._password, etype
                )
                data = self._krb5_client.sendrcv(as_req.to_asn1().dump())
                print(data)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        add_help=True, description="Get TGT from FreeIPA server"
    )
    parser.add_argument(
        "-u", "--username", required=True, action="store", help="username"
    )
    parser.add_argument(
        "-p", "--password", required=True, action="store", help="password"
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

    tgt = GetTgt(options.username, options.password, options.domain, options.ipa_host)
    try:
        tgt.getTgt()
    except UnexpectedKerberosError as e:
        print(e)
