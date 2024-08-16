#!/usr/bin/env python

import argparse
import sys
import logging

from ipapocket.network.krb5 import Krb5Client
from ipapocket.krb5.operations import BaseKrb5Operations
from ipapocket.krb5.crypto.backend import Key
from ipapocket.krb5.crypto import crypto
from ipapocket.krb5.constants import ErrorCodes, KeyUsageTypes
from ipapocket.exceptions.exceptions import UnexpectedKerberosError, UnknownEncPartType
from ipapocket.utils import logger
from ipapocket.krb5.objects import (
    KerberosResponse,
    AsRep,
    EncRepPart,
    KdcRep,
    Ticket,
    TgsRep,
)
from ipapocket.krb5.ccache import Ccache


class GetTgs:
    def __init__(
        self,
        username,
        password,
        domain,
        ipa_host,
        use_ccache,
        service_name,
        ccache_file=None,
    ):
        self._base = BaseKrb5Operations(domain, username, password)
        self._krb5_client = Krb5Client(ipa_host)

        self._username = username
        self._password = password
        self._domain = domain
        self._ipa_host = ipa_host
        self._session_key: Key = None
        self._service_name = service_name
        self._ccache_path = ccache_file

    def _save_ccache(self, kdc_rep, kdc_enc_part):
        ccache = Ccache()
        ccache.set_tgt(kdc_rep, kdc_enc_part)
        ccache.to_file(self._ccache_path)
        logging.info("TGS saved to {}".format(self._ccache_path))

    def _asRep(self, rep: AsRep, key: Key):
        """
        Process AS-REP
        """
        enc_part = EncRepPart.load(
            crypto.decrypt(
                key,
                KeyUsageTypes.AS_REP_ENCPART,
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
        logging.info("got AS-REP successfully")

        # save session key
        self._session_key = Key(kdc_enc_data.key.keytype, kdc_enc_data.key.keyvalue)
        self._tgsReq(rep.kdc_rep.ticket, rep.kdc_rep)

    def _tgsReq(self, ticket: Ticket, kdc_rep: KdcRep):
        """
        Process TGS-REQ
        """
        logging.debug("construct TGS-REQ")
        tgs_req = self._base.tgs_req(
            kdc_rep, ticket, self._session_key, self._service_name
        )
        logging.debug("send TGS-REQ")
        data = self._krb5_client.sendrcv(tgs_req.dump())
        # convert to response type
        response = KerberosResponse.load(data)
        if response.is_krb_error():
            raise UnexpectedKerberosError(response.krb_error.error_code.name)
        else:
            self._tgs_rep(response.tgs_rep)

    def _tgs_rep(self, rep: TgsRep):
        enc_part = EncRepPart.load(
            crypto.decrypt(
                self._session_key,
                KeyUsageTypes.TGS_REP_ENCPART_SESSKEY,
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
            logging.info("got TGS-REP successfully")

    def get_tgs(self):
        logging.debug("construct AS-REQ wihtout PA")
        as_req = self._base.as_req_without_pa()
        logging.debug("send AS-REQ without PA")
        data = self._krb5_client.sendrcv(as_req.dump())
        # convert to response type
        response = KerberosResponse.load(data)
        if response.is_krb_error():
            krb_rep = response.krb_error
            # if error is not NEEDED_PREAUTH
            if krb_rep.error_code != ErrorCodes.KDC_ERR_PREAUTH_REQUIRED:
                raise UnexpectedKerberosError(krb_rep.error_code.name)
            else:
                # get preferred etypes + salt
                self._base.as_req_preffered_etype(krb_rep)
                # generate user secret
                logging.debug("generate user secret based on etype, password and salt")
                self._base.gen_key()
                # construct as-req with PA
                logging.debug("construct AS-REQ with encrypted PA")
                as_req = self._base.as_req_with_pa()
                logging.debug("send AS-REQ with encrypted PA")
                data = self._krb5_client.sendrcv(as_req.dump())
                response = KerberosResponse.load(data)
                if response.is_krb_error():
                    raise UnexpectedKerberosError(response.krb_error.error_code.name)
                else:
                    self._asRep(response.as_rep, self._base.key)
        else:
            # client doesn't need preauth, so we get TGT right now
            logging.debug("recieved AS-REP for user without PA needing")
            self._asRep(response.as_rep, self._base.key)


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
        "-k",
        required=False,
        action="store_true",
        help="Use KRB5CCNAME for TGT CCACHE path",
    )
    parser.add_argument(
        "-s",
        "--service",
        required=False,
        action="store",
        help="Name of service to get ST for (SPN). Default krbtgt/DOMAIN",
    )
    parser.add_argument(
        "--ccache",
        required=False,
        action="store",
        help="Path for CCACHE file to store TGS",
    )

    options = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    if options.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    tgt = GetTgs(
        options.username,
        options.password,
        options.domain,
        options.ipa_host,
        options.k,
        options.service,
        options.ccache,
    )
    try:
        tgt.get_tgs()
    except UnexpectedKerberosError as e:
        print(e)
