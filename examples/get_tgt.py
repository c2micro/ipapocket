import argparse
import sys
import secrets
from datetime import datetime, timezone, timedelta

# hack to import from ipapocket
sys.path.append('.')

from ipapocket.krb5.constants import KdcOptionsTypes, PrincipalType, MessageTypes
from ipapocket.krb5.objects import PrincipalName, KdcOptions, KdcReqBody, Realm, KerberosTime, Int32, UInt32, EncTypes, KdcReq, AsReq
from ipapocket.krb5.crypto import supported_enctypes

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
        # create realm
        realm = Realm(domain)
        # create sname
        server_name = PrincipalName(PrincipalType.NT_PRINCIPAL.value, ['krbtgt', domain])

        current_timestamp = datetime.now(timezone.utc)

        # create KDC request body
        kdc_req_body = KdcReqBody()

        # create KDC options
        kdc_options = KdcOptions()
        kdc_options.add(KdcOptionsTypes.FORWARDABLE)
        kdc_options.add(KdcOptionsTypes.CANONICALIZE)
        kdc_options.add(KdcOptionsTypes.RENEWABLE_OK)

        # generate timestamps for validatity of TGT
        till = KerberosTime(current_timestamp + timedelta(days=1))
        rtime = KerberosTime(current_timestamp + timedelta(days=1))

        # generate nonce
        nonce = UInt32(secrets.randbits(31))

        # set options in request
        kdc_req_body.set_kdc_options(kdc_options)
        # set cname in request
        kdc_req_body.set_cname(username)
        # set realm in request
        kdc_req_body.set_realm(realm)
        # set sname in request
        kdc_req_body.set_sname(server_name)
        # set till in request
        kdc_req_body.set_till(till)
        # set rtime in request
        kdc_req_body.set_rtime(rtime)
        # set nonce in request
        kdc_req_body.set_nonce(nonce)

        # create object with supported encryption types
        etypes = EncTypes(supported_enctypes())
        # set etype in request
        kdc_req_body.set_enctypes(etypes)

        # TODO - PAC

        # create KDC request
        kdc_req = KdcReq()

        # add version of kerberos
        kdc_req.set_pvno(Int32(5))
        # add KDC requst body
        kdc_req.set_req_body(kdc_req_body)
        # add message type
        kdc_req.set_msg_type(Int32(MessageTypes.KRB_AS_REQ.value))

        # create AS-REQ
        as_req = AsReq()
        as_req.set_req(kdc_req)

        print(as_req.to_asn1().debug())
        

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

