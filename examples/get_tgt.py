import argparse
import sys
from datetime import datetime, timezone

# hack to import from ipapocket
sys.path.append('.')

from ipapocket.krb5.constants import KdcOptionsTypes, PrincipalType
from ipapocket.krb5.objects import PrincipalName, KdcOptions, KdcReqBody

class GetTgt():
    def __init__(self, username, password, domain, ipa_host):
        self._username = username
        self._password = password
        self._domain = domain
        self._ipa_host = ipa_host

    def getTgt(self):
        # convert domain name to upper case
        domain = self._domain.upper()
        # create UPN
        username = PrincipalName(PrincipalType.NT_PRINCIPAL.value, self._username)
        
        current_timestamp = datetime.now(timezone.utc)

        # create KDC request body
        kdcReqBody = KdcReqBody()

        # create KDC options
        kdcOptions = KdcOptions()
        kdcOptions.add(KdcOptionsTypes.FORWARDABLE)
        kdcOptions.add(KdcOptionsTypes.CANONICALIZE)
        kdcOptions.add(KdcOptionsTypes.RENEWABLE_OK)
        kdcReqBody.setKdcOptions(kdcOptions)

        print(kdcReqBody.to_asn1().debug())
        

if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=True, description="Get TGT from FreeIPA server")
    parser.add_argument('-u', '--username', required=True, action='store', help="username")
    parser.add_argument('-p', '--password', required=True, action='store', help="password")
    parser.add_argument('-d', '--domain', required=True, action='store', help="Domain name, e.g. ipa.test")
    parser.add_argument('-H', '--ipa-host', required=True, action='store', help="IP address or FQDN of FreeIPA KDC")

    options = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    
    tgt = GetTgt(options.username, options.password, options.domain, options.ipa_host)
    tgt.getTgt()

