import argparse
import sys
import logging

# hack to import from ipapocket
sys.path.append(".")

from ipapocket.network.krb5 import Krb5Client
from ipapocket.krb5.operations import (
    as_req_wihtout_pa,
    as_req_with_pa,
    as_req_get_preferred_etype,
    _krb_key,
)
from ipapocket.krb5.crypto.base import Key, _get_etype_profile
from ipapocket.krb5.constants import ErrorCodes, KeyUsageTypes
from ipapocket.exceptions.exceptions import UnexpectedKerberosError, UnknownEncPartType
from ipapocket.utils import logger
from ipapocket.krb5.objects import KerberosResponse, AsRep, EncRepPart
from ipapocket.krb5.ccache import Ccache


class GetTgt:
    def __init__(self, username, password, domain, ipa_host, ccache_file=None):
        self._username = username
        self._password = password
        self._domain = domain
        self._ipa_host = ipa_host
        self._ccache_path = ccache_file
        self._krb5_client = Krb5Client(ipa_host)

    def _save_ccache(self, kdc_rep, kdc_enc_part):
        ccache = Ccache()
        ccache.set_tgt(kdc_rep, kdc_enc_part)
        ccache.to_file(self._ccache_path)
        logging.info("TGT saved to {}".format(self._ccache_path))

    def _asRep(self, rep: AsRep, key: Key):
        part = _get_etype_profile(key.enctype).decrypt(
            key, KeyUsageTypes.AS_REP_ENCPART.value, rep.kdc_rep.enc_part.cipher
        )
        enc_part = EncRepPart.load(part)
        if enc_part.is_enc_as_rep():
            kdc_enc_data = enc_part.enc_as_rep_part.enc_kdc_rep_part
            logging.debug("encrypted part from AS-REP (microsoft way)")
        elif enc_part.is_enc_tgs_rep():
            kdc_enc_data = enc_part.enc_tgs_rep_part.enc_kdc_rep_part
            logging.debug("encrypted part from TGS-REP (linux way)")
        else:
            raise UnknownEncPartType("XXX")
        if self._ccache_path is not None:
            self._save_ccache(rep.kdc_rep, kdc_enc_data)
        else:
            logging.info("got AS-REP successfully")

    def getTgt(self):
        logging.debug("construct AS-REQ wihtout PA")
        as_req = as_req_wihtout_pa(self._domain, self._username)
        logging.debug("send AS-REQ without PA")
        data = self._krb5_client.sendrcv(as_req.to_asn1().dump())
        # convert to response type
        response = KerberosResponse.load(data)
        if response.is_krb_error():
            krb_rep = response.krb_error
            # if error is not NEEDED_PREAUTH
            if krb_rep.error_code != ErrorCodes.KDC_ERR_PREAUTH_REQUIRED:
                raise UnexpectedKerberosError(krb_rep.error_code.name)
            else:
                # get preferred etypes + salt
                etype, salt = as_req_get_preferred_etype(krb_rep)
                logging.debug("construct AS-REQ with encrypted PA")
                as_req = as_req_with_pa(
                    self._domain, self._username, self._password, etype, salt
                )
                logging.debug("send AS-REQ with encrypted PA")
                data = self._krb5_client.sendrcv(as_req.to_asn1().dump())
                response = KerberosResponse.load(data)
                if response.is_krb_error():
                    raise UnexpectedKerberosError(response.krb_error)
                else:
                    key = _krb_key(etype, self._password, salt)
                    self._asRep(response.as_rep, key)
        else:
            # client doesn't need preauth, so we get TGT right now
            # TODO
            logging.debug("recieved AS-REP for user without PA needing")
            pass


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
    parser.add_argument(
        "--ccache",
        required=False,
        action="store",
        help="Path for CCACHE file to store TGT",
    )

    options = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    if options.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    tgt = GetTgt(
        options.username,
        options.password,
        options.domain,
        options.ipa_host,
        options.ccache,
    )
    try:
        tgt.getTgt()
    except UnexpectedKerberosError as e:
        print(e)
