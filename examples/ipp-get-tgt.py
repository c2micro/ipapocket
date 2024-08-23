#!/usr/bin/env python

import argparse
import sys
import logging

from ipapocket.network.krb5 import Krb5Network
from ipapocket.krb5.operations import BaseKrb5Operations
from ipapocket.krb5.crypto.backend import Key
from ipapocket.krb5.crypto import crypto
from ipapocket.krb5.constants import ErrorCode, KeyUsageType
from ipapocket.exceptions.exceptions import UnexpectedKerberosError, UnknownEncPartType
from ipapocket.utils import logger
from ipapocket.krb5.types import AsRep, EncRepPart
from ipapocket.krb5.credentials.ccache import Ccache
from binascii import unhexlify


class GetTgt:
    def __init__(
        self, username, password, domain, ipa_host, service, renewable, ccache_file=None
    ):
        self._base = BaseKrb5Operations(
            domain=domain, username=username, password=password
        )
        self._krb5_client = Krb5Network(ipa_host)

        self._username = username
        self._password = password
        self._domain = domain
        self._ipa_host = ipa_host
        self._ccache_path = ccache_file
        self._service_name = service
        self._renewable = renewable

    def _save_ccache(self, kdc_rep, kdc_enc_part):
        ccache = Ccache()
        ccache.set_tgt(kdc_rep, kdc_enc_part)
        ccache.to_file(self._ccache_path)
        logging.info("TGT saved to {}".format(self._ccache_path))

    def _as_rep(self, rep: AsRep, key: Key):
        enc_part = EncRepPart.load(
            crypto.decrypt(
                key,
                KeyUsageType.AS_REP_ENCPART,
                rep.kdc_rep.enc_part.cipher,
            )
        )
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

    def get_tgt(self):
        logging.debug("construct AS-REQ wihtout PA")
        as_req = self._base.as_req_without_pa(service=self._service_name)
        logging.debug("send AS-REQ without PA")
        # convert to response type
        response = self._krb5_client.sendrcv(as_req)
        if response.is_krb_error():
            krb_rep = response.krb_error
            # if error is not NEEDED_PREAUTH
            if krb_rep.error_code != ErrorCode.KDC_ERR_PREAUTH_REQUIRED:
                raise UnexpectedKerberosError(krb_rep.error_code.name)
            else:
                # get preferred etypes + salt
                self._base.as_req_preffered_etype(krb_rep)
                # generate user secret
                logging.debug("generate user secret based on etype, password and salt")
                self._base.gen_key()
                # construct as-req with PA
                logging.debug("construct AS-REQ with encrypted PA")
                as_req = self._base.as_req_with_pa(
                    service=self._service_name, renewable=self._renewable
                )
                logging.debug("send AS-REQ with encrypted PA")
                response = self._krb5_client.sendrcv(as_req)
                if response.is_krb_error():
                    raise UnexpectedKerberosError(response.krb_error.error_code.name)
                else:
                    self._as_rep(response.as_rep, self._base.key)
        else:
            # client doesn't need preauth, so we get TGT right now
            logging.debug("recieved AS-REP for user without PA needing")
            self._as_rep(response.as_rep, self._base.key)


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
        "-s",
        "--service",
        required=False,
        action="store",
        help="Name of service to get TGT for (SPN). Default krbtgt/DOMAIN",
    )
    parser.add_argument(
        "--renewable",
        required=False,
        action="store_true",
        help="Make TGT renewable (set KDC option in AP-REQ)",
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
        options.service,
        options.renewable,
        options.ccache,
    )
    try:
        tgt.get_tgt()
    except UnexpectedKerberosError as e:
        print(e)
