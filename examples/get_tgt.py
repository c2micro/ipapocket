import argparse
import sys

# hack to import from ipapocket
sys.path.append('.')

from ipapocket.krb5.types import PrincipalName
from ipapocket.krb5.constants import PrincipalType

class GetTgt():
    def __init__(self, username, password, domain, ipa_host):
        self._username = username
        self._password = password
        self._domain = domain
        self._ipa_host = ipa_host

    def getTgt(self):
        # convert domain name to upper case
        domain = self._domain.upper()
        # username = PrincipalName(PrincipalType.NT_PRINCIPAL.value, self._username)
        username = PrincipalName(99999999999999999999999, self._username)
        print(username.to_asn1().debug())

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

