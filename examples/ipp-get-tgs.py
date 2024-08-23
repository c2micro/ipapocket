#!/usr/bin/env python

import argparse
import sys
import logging
import os
from datetime import datetime, timedelta, timezone
import secrets

from ipapocket.krb5.credentials import Ccache
from ipapocket.network.krb5 import Krb5Network
from ipapocket.krb5.crypto import *
from ipapocket.krb5.constants import (
    KdcOptionsType,
    NameType,
    KRB5_VERSION,
    PreAuthenticationDataType,
    MessageType,
)
from ipapocket.exceptions.exceptions import UnexpectedKerberosError, UnknownEncPartType
from ipapocket.utils import logger
from ipapocket.krb5.types import (
    EncTypes,
    KdcReq,
    KdcReqBody,
    PrincipalName,
    KdcOptions,
    KerberosTime,
    UInt32,
    Microseconds,
    Authenticator,
    Checksum,
    EncryptedData,
    ApReq,
    ApOptions,
    MethodData,
    PaData,
    TgsReq,
    EncRepPart,
)


class GetTgs:
    _tgt_ccache: Ccache = None # ccache object with TGT
    _tgt_ccache_id: int = None # ID of credential in CCACHE with TGT
    _socket: Krb5Network = None # socket object
    _domain: str = None
    _spn: str = None
    _tgs_ccache_path: str = None # ccache path to save TGS
    _tgs_renewable: bool = False # set RENEWABLE KDC option to TGS-REQ

    def __init__(
        self,
        domain,
        ipa_host,
        ccache_id,
        spn,
        renewable,
        ccache_file=None,
    ):
        self._socket = Krb5Network(ipa_host)
        self._domain = domain
        self._spn = spn
        self._tgs_ccache_path = ccache_file
        self._tgs_renewable = renewable
        self._tgt_ccache = Ccache.from_file(os.getenv("KRB5CCNAME"))
        if ccache_id is None:
            self._tgt_ccache_id = 0
        else:
            self._tgt_ccache_id = int(ccache_id)

    def get_tgs(self):
        """
        1. parse CCACHE
        2. create TGS-REQ packet
        3. send packet and process response
        """
        logging.debug("get TGT from KRB5CCNAME path")
        tgt = self._tgt_ccache.get_tgt(self._tgt_ccache_id)
        logging.debug("construct TGS-REQ packet")
        cur_ts = datetime.now(timezone.utc)
        # prepare domain
        if self._domain is None or self._domain == "":
            domain = tgt.kdc_rep.crealm.realm.value.upper()
        else:
            domain = self._domain.upper()
        # prepare spn
        if self._spn is None or self._spn == "":
            spn = "krbtgt/%s" % domain
        else:
            spn = self._spn
        # prepare etype
        etype = EncTypes(tgt.session_key.enctype)

        # create KDC request body
        kdc_rbody = KdcReqBody()

        # create KDC options
        kdc_opts = KdcOptions()
        kdc_opts.add(KdcOptionsType.FORWARDABLE)
        kdc_opts.add(KdcOptionsType.CANONICALIZE)
        if self._tgs_renewable:
            kdc_opts.add(KdcOptionsType.RENEWABLE)

        # set kdc options
        kdc_rbody.kdc_options = kdc_opts
        # set realm
        kdc_rbody.realm = domain
        # set sname
        kdc_rbody.sname = PrincipalName(NameType.NT_PRINCIPAL, spn)
        # set till timestamp
        kdc_rbody.till = KerberosTime(cur_ts + timedelta(days=1))
        # set nonce
        kdc_rbody.nonce = UInt32.load(secrets.randbits(31))
        # set etype
        kdc_rbody.etype = etype

        # create KDC request
        kdc_r = KdcReq()

        # calculate checksum for KDC request body
        cksum = Checksum()
        cksum.cksumtype = cksum_for_etype(tgt.session_key.enctype)
        cksum.checksum = checksum(
            tgt.session_key,
            KeyUsageType.TGS_REQ_AUTH_CKSUM,
            kdc_rbody.dump(),
        )

        # create authenticator
        authenticator = Authenticator()
        authenticator.authenticator_vno = KRB5_VERSION
        authenticator.crealm = tgt.kdc_rep.crealm
        authenticator.cname = tgt.kdc_rep.cname
        authenticator.cusec = Microseconds(cur_ts.microsecond)
        authenticator.ctime = KerberosTime(cur_ts)
        authenticator.cksum = cksum
        authenticator.seq_number = 0

        # encrypt authenticator
        enc_authenticator = EncryptedData()
        enc_authenticator.etype = tgt.session_key.enctype
        enc_authenticator.cipher = encrypt(
            tgt.session_key, KeyUsageType.TGS_REQ_AUTH, authenticator.dump()
        )

        # create ap-req
        ap_req = ApReq()
        ap_req.pvno = KRB5_VERSION
        ap_req.msg_type = MessageType.KRB_AP_REQ
        ap_req.ap_options = ApOptions()
        ap_req.ticket = tgt.kdc_rep.ticket
        ap_req.authenticator = enc_authenticator

        # create method data with authenticator
        method_data = MethodData()
        pa_data = PaData(PreAuthenticationDataType.PA_TGS_REQ, ap_req.dump())
        method_data.add(pa_data)

        # add version of kerberos
        kdc_r.pvno = KRB5_VERSION
        # add KDC requst body
        kdc_r.req_body = kdc_rbody
        # add message type
        kdc_r.msg_type = MessageType.KRB_TGS_REQ
        # add pa data (ap-req with authenticator)
        kdc_r.padata = method_data

        # create TGS-REQ
        tgs_req = TgsReq(kdc_r)

        logging.debug("send TGS-REQ packet")
        rep = self._socket.sendrcv(tgs_req)
        if rep.is_krb_error():
            raise UnexpectedKerberosError(rep.krb_error.error_code.name, rep.krb_error.e_text)
        else:
            epart = EncRepPart.load(
                decrypt(
                    tgt.session_key,
                    KeyUsageType.TGS_REP_ENCPART_SESSKEY,
                    rep.tgs_rep.kdc_rep.enc_part.cipher,
                )
            )
            # get KDC response part
            if epart.is_enc_as_rep():
                logging.debug("encrypted part from AS-REP (microsoft way)")
                kdc_edata = epart.enc_as_rep_part.enc_kdc_rep_part
            elif epart.is_enc_tgs_rep():
                logging.debug("encrypted part from TGS-REP (linux way)")
                kdc_edata = epart.enc_tgs_rep_part.enc_kdc_rep_part
            else:
                raise UnknownEncPartType("something go wrong")

            # save to ccache
            if self._tgs_ccache_path is not None or self._tgs_ccache_path != "":
                self

        if self._tgs_ccache_path is not None:
            ccache = Ccache()
            ccache.set_tgt(rep.tgs_rep.kdc_rep, kdc_edata)
            ccache.to_file(self._tgs_ccache_path)
            logging.info("TGS saved to {}".format(self._tgs_ccache_path))
        else:
            logging.info("got TGS-REP successfully")


if __name__ == "__main__":
    """
    As FreeIPA has a banch of different PA types, first step must be getting TGT via needing ipp-get-tgt-<method>.py
    and save its in CCACHE. This script only accept TGT from CCACHE (KRB5CCNAME)!
    """
    logger.init()
    parser = argparse.ArgumentParser(
        add_help=True, description="Get TGS from FreeIPA server"
    )
    parser.add_argument(
        "-d",
        "--domain",
        required=False,
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
        "-i",
        required=False,
        action="store",
        help="Specify ID of credentials in CCACHE (by default will take first one)",
    )
    parser.add_argument(
        "-s",
        "--service",
        required=False,
        action="store",
        help="Name of service to get ST for (SPN). Default krbtgt/DOMAIN",
    )
    parser.add_argument(
        "--renewable",
        required=False,
        action="store_true",
        help="Make TGS renewable (set KDC option in TGS-REQ)",
    )
    parser.add_argument(
        "-c",
        "--ccache",
        required=False,
        action="store",
        help="Path for CCACHE file to save TGS",
    )

    options = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    if options.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        GetTgs(
            options.domain,
            options.ipa_host,
            options.i,
            options.service,
            options.renewable,
            options.ccache,
        ).get_tgs()
    except UnexpectedKerberosError as e:
        print(e)
        sys.exit(1)
