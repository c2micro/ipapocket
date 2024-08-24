#!/usr/bin/env python

import argparse
import sys
import logging
from datetime import datetime, timedelta, timezone
import secrets
import base64

from ipapocket.network.krb5 import Krb5Network
from ipapocket.exceptions.exceptions import (
    UnexpectedKerberosError,
    UnknownEncPartType,
    NoSupportedEtypes,
)
from ipapocket.utils import logger
from ipapocket.krb5.credentials import Ccache, Kirbi
from ipapocket.krb5.types import (
    KdcReqBody,
    KdcReq,
    KdcOptions,
    UInt32,
    PrincipalName,
    KerberosTime,
    Realm,
    EncTypes,
    AsReq,
    MethodData,
    EtypeInfo,
    EtypeInfo2,
    PaEncTsEnc,
    PaData,
    EncryptedData,
    EncRepPart,
    Tgt,
)
from ipapocket.krb5.constants import (
    KeyUsageType,
    MessageType,
    KdcOptionsType,
    NameType,
    ErrorCode,
    PreAuthenticationDataType,
    KRB5_VERSION,
)
from ipapocket.krb5.crypto import string_to_key, decrypt, supported_etypes, encrypt


class GetTgt:
    _username: str = None
    _password: str = None
    _domain: str = None
    _socket: Krb5Network = None
    _spn: str = None
    _tgt_renewable: bool = False  # set RENEWABLE KDC option in AS-REQ
    _tgt_ccache_path: str = None
    _tgt_kirbi_path: str = None

    def __init__(
        self,
        username,
        password,
        domain,
        ipa_host,
        service,
        renewable,
        ccache_file,
        kirbi_file,
    ):
        self._socket = Krb5Network(ipa_host)
        self._username = username
        self._password = password
        self._domain = domain
        self._tgt_renewable = renewable
        self._tgt_ccache_path = ccache_file
        self._tgt_kirbi_path = kirbi_file

    def get_tgt(self):
        """
        1. Send AS-REQ without preauth to get salt of user
        2. Send AS-REQ with encrypted timestamp
        3. Get salt from AS-REP (to handle case with no-preauth)
        3. Save TGT
        """
        logging.debug("construct AS-REQ without PA")
        cur_ts = datetime.now(timezone.utc)
        domain = self._domain.upper()
        # prepare spn
        if self._spn is None or self._spn == "":
            spn = "krbtgt/%s" % domain
        else:
            spn = self._spn

        # create KDC request body
        kdc_rbody = KdcReqBody()

        # create KDC options
        kdc_opts = KdcOptions()
        kdc_opts.add(KdcOptionsType.FORWARDABLE)
        kdc_opts.add(KdcOptionsType.CANONICALIZE)
        kdc_opts.add(KdcOptionsType.RENEWABLE_OK)
        if self._tgt_renewable:
            kdc_opts.add(KdcOptionsType.RENEWABLE)

        # set kdc options
        kdc_rbody.kdc_options = kdc_opts
        # set client name
        kdc_rbody.cname = PrincipalName(NameType.NT_PRINCIPAL, self._username)
        # set realm
        kdc_rbody.realm = Realm(domain)
        # set service name
        kdc_rbody.sname = PrincipalName(NameType.NT_SRV_INST, spn)
        # set till
        kdc_rbody.till = KerberosTime(cur_ts + timedelta(days=1))
        # set rtime
        kdc_rbody.rtime = KerberosTime(cur_ts + timedelta(days=1))
        # set nonce
        kdc_rbody.nonce = UInt32(secrets.randbits(31))
        # set etype (all supported list)
        kdc_rbody.etype = EncTypes(supported_etypes())

        # create KDC request
        kdc_r = KdcReq()

        # set body
        kdc_r.req_body = kdc_rbody
        # set message type
        kdc_r.msg_type = MessageType.KRB_AS_REQ

        # create AS-REQ
        as_req = AsReq(kdc_r)

        logging.debug("send AS-REQ without PA")
        rep = self._socket.sendrcv(as_req)
        if rep.is_krb_error():
            # get salt and send AS-REQ with PA
            if rep.krb_error.error_code != ErrorCode.KDC_ERR_PREAUTH_REQUIRED:
                raise UnexpectedKerberosError(
                    rep.krb_error.error_code.name, rep.krb_error.e_text
                )
            else:
                # get salt
                salt_found = False
                for padata in MethodData.load(rep.krb_error.e_data).padatas:
                    # from https://www.rfc-editor.org/rfc/rfc4120#section-5.2.7.5 - might be ONLY ONE ETYPE-ENTRY in sequence of each
                    if padata.type == PreAuthenticationDataType.PA_ETYPE_INFO:
                        value = EtypeInfo.load(padata.value).entries[0]
                        if value.etype in supported_etypes():
                            logging.debug(
                                "ETYPE-INFO with etype '{}' and salt '{}'".format(
                                    value.etype.name, value.salt
                                )
                            )
                            etype = value.etype
                            salt = value.salt
                            salt_found = True
                            break
                    if padata.type == PreAuthenticationDataType.PA_ETYPE_INFO2:
                        value = EtypeInfo2.load(padata.value).entries[0]
                        if value.etype in supported_etypes():
                            logging.debug(
                                "ETYPE-INFO2 with etype '{}' and salt '{}'".format(
                                    value.etype.name, value.salt
                                )
                            )
                            etype = value.etype
                            salt = value.salt.value
                            salt_found = True
                            break
                if not salt_found:
                    raise NoSupportedEtypes()

                logging.debug("construct AS-REQ with PA")
                cur_ts = datetime.now(timezone.utc)
                # create client key
                key = string_to_key(etype, self._password, salt)
                # take previous kdc request body and modify some fields
                kdc_rbody.till = KerberosTime(cur_ts + timedelta(days=1))
                kdc_rbody.rtime = None
                kdc_rbody.nonce = UInt32(secrets.randbits(31))
                kdc_rbody.etype = EncTypes(etype)
                # create new kdc request
                kdc_r = KdcReq()
                # encrypt timestamp
                enc_ts = encrypt(
                    key,
                    KeyUsageType.AS_REQ_PA_ENC_TIMESTAMP,
                    PaEncTsEnc(cur_ts, cur_ts.microsecond).dump(),
                )
                # create padata
                mdata = MethodData()
                padata = PaData()
                padata.type = PreAuthenticationDataType.PA_ENC_TIMESTAMP
                padata.value = EncryptedData(etype, KRB5_VERSION, enc_ts)
                mdata.add(padata)
                # set preauthentication data to kdc request
                kdc_r.padata = mdata
                # set message type
                kdc_r.msg_type = MessageType.KRB_AS_REQ
                # set body
                kdc_r.req_body = kdc_rbody
                # create AS-REQ
                as_req = AsReq(kdc_r)

                logging.debug("send AS-REQ with PA")
                rep = self._socket.sendrcv(as_req)
                if rep.is_krb_error():
                    raise UnexpectedKerberosError(
                        rep.krb_error.error_code.name, rep.krb_error.e_text
                    )
                else:
                    kdc_rep = rep.as_rep.kdc_rep
        else:
            logging.info("user {} doesn't need preauth!".format(self._username))
            kdc_rep = rep.as_rep.kdc_rep

        # to handle case with no-preauth -> get salt one more time
        # get salt
        salt_found = False
        for padata in MethodData.load(kdc_rep.padata).padatas:
            # from https://www.rfc-editor.org/rfc/rfc4120#section-5.2.7.5 - might be ONLY ONE ETYPE-ENTRY in sequence of each
            if padata.type == PreAuthenticationDataType.PA_ETYPE_INFO:
                value = EtypeInfo.load(padata.value).entries[0]
                if value.etype in supported_etypes():
                    logging.debug(
                        "ETYPE-INFO with etype '{}' and salt '{}' in AS-REP".format(
                            value.etype.name, value.salt
                        )
                    )
                    etype = value.etype
                    salt = value.salt
                    salt_found = True
                    break
            if padata.type == PreAuthenticationDataType.PA_ETYPE_INFO2:
                value = EtypeInfo2.load(padata.value).entries[0]
                if value.etype in supported_etypes():
                    logging.debug(
                        "ETYPE-INFO2 with etype '{}' and salt '{}' in AS-REP".format(
                            value.etype.name, value.salt
                        )
                    )
                    etype = value.etype
                    salt = value.salt.value
                    salt_found = True
                    break
        if not salt_found:
            raise NoSupportedEtypes("unable find salt in AS-REP")
        # create key
        key = string_to_key(etype, self._password, salt)
        # decrypt encrypted part of response
        epart = EncRepPart.load(
            decrypt(key, KeyUsageType.AS_REP_ENCPART, kdc_rep.enc_part.cipher)
        )
        if epart.is_enc_as_rep():
            logging.debug("encrypted part from AS-REP (microsoft way)")
            kdc_edata = epart.enc_as_rep_part.enc_kdc_rep_part
        elif epart.is_enc_tgs_rep():
            logging.debug("encrypted part from TGS-REP (linux way)")
            kdc_edata = epart.enc_tgs_rep_part.enc_kdc_rep_part
        else:
            raise UnknownEncPartType("something go wrong")

        # create tgt for further processing
        tgt = Tgt()
        tgt.session_key = kdc_edata.key
        tgt.kdc_rep = kdc_rep
        tgt.epart = kdc_edata

        # do we need print TGS in kirbi to stdout
        need_output = True

        if self._tgt_ccache_path is not None and self._tgt_ccache_path != "":
            ccache = Ccache()
            ccache.add_tgt(tgt)
            ccache.to_file(self._tgt_ccache_path)
            logging.info("[CCACHE] TGT saved to {}".format(self._tgt_ccache_path))
            need_output = False

        if self._tgt_kirbi_path is not None and self._tgt_kirbi_path != "":
            kirbi = Kirbi.from_tgt(tgt)
            kirbi.to_file(self._tgt_kirbi_path)
            logging.info("[KIRBI] TGT saved to {}".format(self._tgt_kirbi_path))
            need_output = False

        if need_output:
            kirbi = Kirbi.from_tgs(tgt)
            logging.info("TGT in KIRBI base64: {}".format(kirbi.to_b64()))


if __name__ == "__main__":
    logger.init()
    parser = argparse.ArgumentParser(
        add_help=True, description="Get TGT from FreeIPA server (normal password flow)"
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
        "-c",
        "--ccache",
        required=False,
        action="store",
        help="Path to save TGT in CCACHE format",
    )
    parser.add_argument(
        "-k",
        "--kirbi",
        required=False,
        action="store",
        help="Path to save TGT in KIRBI format",
    )

    options = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    if options.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        GetTgt(
            options.username,
            options.password,
            options.domain,
            options.ipa_host,
            options.service,
            options.renewable,
            options.ccache,
            options.kirbi,
        ).get_tgt()
    except UnexpectedKerberosError as e:
        print(e)
