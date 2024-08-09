import argparse
import sys
import logging

# hack to import from ipapocket
sys.path.append(".")

from ipapocket.network.krb5 import Krb5Client
from ipapocket.krb5.operations import (
    as_req_wihtout_pa,
    as_req_with_pa,
    get_preferred_etype,
    _krb_key,
)
from ipapocket.krb5.asn1 import *
from ipapocket.krb5.crypto.base import Key, _get_etype_profile
from ipapocket.krb5.constants import ErrorCodes, KeyUsageTypes, EncryptionTypes
from ipapocket.exceptions.exceptions import UnexpectedKerberosError, UnknownEncPartType
from ipapocket.utils import logger


class GetTgt:
    def __init__(self, username, password, domain, ipa_host):
        self._username = username
        self._password = password
        self._domain = domain
        self._ipa_host = ipa_host
        self._krb5_client = Krb5Client(ipa_host)

    def asRep(self, rep: AsRepAsn1, key: Key):
        dec_part = _get_etype_profile(key.enctype).decrypt(
            key, KeyUsageTypes.AS_REP_ENCPART.value, rep["enc-part"]["cipher"]
        )
        enc_part = EncRepPartAsn1.load(dec_part)
        if enc_part.name == "ENC-AS-REP-PART":
            logging.debug("encrypted part from AS-REP (microsoft way)")
        elif enc_part.name == "ENC-TGS-REP-PART":
            logging.debug("encrypted part from TGS-REP (linux way)")
        else:
            raise UnknownEncPartType(enc_part.name)
        logging.info("got valid AS-REP")
        enc_part = enc_part.native
        # session_key = Key(EncryptionTypes(enc_part["key"]["keytype"]), enc_part["key"]["keyvalue"])
        # print(session_key)

    def getTgt(self):
        logging.debug("construct AS-REQ wihtout PA")
        as_req = as_req_wihtout_pa(self._domain, self._username)
        logging.debug("send AS-REQ without PA")
        data = self._krb5_client.sendrcv(as_req.to_asn1().dump())
        # convert to response type
        krb_msg = KerberosResponseAsn1.load(data)
        if krb_msg.name != "KRB-ERROR":
            # client doesn't need preauth, so we get TGT right now
            # TODO
            logging.debug("recieved AS-REP for user without PA needing")
            pass
        else:
            if (
                krb_msg.native["error-code"]
                != ErrorCodes.KDC_ERR_PREAUTH_REQUIRED.value
            ):
                raise UnexpectedKerberosError(krb_msg)
            else:
                # get preferred etypes + salt
                etype, salt = get_preferred_etype(krb_msg)
                logging.debug("construct AS-REQ with encrypted PA")
                as_req = as_req_with_pa(
                    self._domain, self._username, self._password, etype, salt
                )
                logging.debug("send AS-REQ with encrypted PA")
                data = self._krb5_client.sendrcv(as_req.to_asn1().dump())
                krb_msg = KerberosResponseAsn1.load(data)
                if krb_msg.name != "KRB-ERROR":
                    # calculate key one more time (TODO)
                    krb_key = _krb_key(etype, self._password, salt)
                    self.asRep(krb_msg.native, krb_key)
                else:
                    raise UnexpectedKerberosError(krb_msg)


if __name__ == "__main__":
    logger.init()
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
    parser.add_argument(
        "-v",
        "--verbose",
        required=False,
        action="store_true",
        help="Verbose mode",
    )

    options = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    if options.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    tgt = GetTgt(options.username, options.password, options.domain, options.ipa_host)
    try:
        tgt.getTgt()
    except UnexpectedKerberosError as e:
        print(e)
