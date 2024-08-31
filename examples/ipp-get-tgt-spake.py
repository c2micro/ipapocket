#!/usr/bin/env python

import argparse
import sys
import logging
from datetime import datetime, timedelta, timezone
import secrets

from ipapocket.network.krb5 import Krb5Network
from ipapocket.exceptions.exceptions import (
    UnexpectedKerberosError,
    UnknownEncPartType,
    NoSupportedEtypes,
    NoSpakeChallenge,
    NoFxCookie,
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
    SpakeResponse,
    EtypeInfo2,
    PaData,
    SpakeSecondFactor,
    EncryptedData,
    EncRepPart,
    Tgt,
    PaSpake,
)
from ipapocket.krb5.constants import (
    KeyUsageType,
    MessageType,
    KdcOptionsType,
    NameType,
    ErrorCode,
    PreAuthenticationDataType,
    SpakeSecondFactorType,
)
from ipapocket.krb5.crypto import (
    string_to_key,
    decrypt,
    supported_etypes,
    encrypt,
    supported_groups,
    get_group_profile,
)

from binascii import hexlify

# TODO - AES128-SHA256/AES256-SHA384


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
        self._spn = service

    def get_tgt(self):
        """
        1. Send AS-REQ without preauth to get salt of user and SPAKE challenge
        2. Send AS-REQ with encrypted SpakeSecondFactor
        3. Decrypt with derived K'[0]
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
                salt_found = False
                spake_challenge_found = False
                cookie_found = False
                for padata in MethodData.load(rep.krb_error.e_data).padatas:
                    # from https://datatracker.ietf.org/doc/draft-ietf-kitten-krb-spake-preauth/13/ - might be ONLY ONE ETYPE-ENTRY in sequence of each
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
                    if padata.type == PreAuthenticationDataType.SPAKE_CHALLENGE:
                        paspake = PaSpake.load(padata.value)
                        # TODO - dirty
                        spake_challenge = paspake.challenge
                        if spake_challenge.group in supported_groups():
                            logging.debug(
                                "SPAKE challenge with group {}".format(
                                    spake_challenge.group.name
                                )
                            )
                            spake_challenge_found = True
                    if padata.type == PreAuthenticationDataType.PA_FX_COOKIE:
                        cookie = padata.value
                        cookie_found = True
                if not salt_found:
                    raise NoSupportedEtypes()
                if not spake_challenge_found:
                    # TODO
                    raise NoSpakeChallenge()
                if not cookie_found:
                    # TODO
                    raise NoFxCookie()
                # logic of next part (based on RFC draft and tests)
                # 1. calculate client key
                # 2. derive w bytes via PRF+ function
                # 3. generate client public key based on ECC (S)
                # 4. create shared K key (K)
                # 5. calculate transcript hash (first iteration based on SpakeChallenge asn1 dump, second based on client public key)
                # 6. create KDC request body (we can reuse previous one)
                # 7. derive K'[n] key
                # 8. ...
                # calculate key for user with salt
                client_key = string_to_key(etype, self._password, salt)
                # derive w bytes
                w = get_group_profile(spake_challenge.group).derive_wbytes(client_key)
                # generate public key
                S, y = get_group_profile(spake_challenge.group).calculate_public(w)
                logging.debug("SPAKE client public key {}".format(hexlify(S).decode()))
                # calculate group shared secret
                K = get_group_profile(spake_challenge.group).calculate_shared(
                    spake_challenge.pubkey, y, w
                )
                logging.debug(
                    "SPAKE shared group secret {}".format(hexlify(K).decode())
                )
                # calculate transcript hash
                thash = get_group_profile(spake_challenge.group).hashmod.new(
                    32 * b"\x00"
                )
                thash.update(spake_challenge.dump())
                thash = get_group_profile(spake_challenge.group).hashmod.new(
                    thash.digest()
                )
                thash.update(S)
                thash = thash.digest()
                logging.debug(
                    "SPAKE final transcript hash {}".format(hexlify(thash).decode())
                )
                # update kdc_rbody
                cur_ts = datetime.now(timezone.utc)
                kdc_rbody.till = KerberosTime(cur_ts + timedelta(days=1))
                kdc_rbody.nonce = UInt32(secrets.randbits(31))
                kdc_rbody.etype = EncTypes(etype)
                # get K'[N]
                k_0 = get_group_profile(spake_challenge.group).derive_k0(
                    client_key, kdc_rbody.dump(), w, K, thash
                )
                k_1 = get_group_profile(spake_challenge.group).derive_k1(
                    client_key, kdc_rbody.dump(), w, K, thash
                )
                logging.debug("SPAKE K'[0]: {}".format(hexlify(k_0.contents).decode()))
                logging.debug("SPAKE K'[1]: {}".format(hexlify(k_0.contents).decode()))
                # create KDC request
                kdc_r = KdcReq()

                # create padata
                mdata = MethodData()

                # create PADATA FX-COOKIE
                padata_cookie = PaData()
                padata_cookie.type = PreAuthenticationDataType.PA_FX_COOKIE
                padata_cookie.value = cookie
                mdata.add(padata_cookie)

                # create PADATA PA-SPAKE
                # second factor
                spake_factor = SpakeSecondFactor()
                spake_factor.type = SpakeSecondFactorType.SF_NONE
                # response
                spake_rep = SpakeResponse()
                spake_rep.pubkey = S
                spake_rep.factor = EncryptedData(
                    etype,
                    None,
                    encrypt(
                        k_1,
                        KeyUsageType.KEY_USAGE_SPAKE,
                        spake_factor.dump(),
                    ),
                )
                # pa spake
                paspake = PaSpake()
                paspake.response = spake_rep
                padata_spake = PaData()
                padata_spake.type = PreAuthenticationDataType.SPAKE_CHALLENGE
                padata_spake.value = paspake.dump()
                mdata.add(padata_spake)

                # set body
                kdc_r.req_body = kdc_rbody
                # set message type
                kdc_r.msg_type = MessageType.KRB_AS_REQ
                # set preauthentication data to kdc request
                kdc_r.padata = mdata

                # create AS-REQ
                as_req = AsReq(kdc_r)

                logging.debug("send AS-REQ with PA-SPAKE and FX-COOKIE")
                rep = self._socket.sendrcv(as_req)
                if rep.is_krb_error():
                    raise UnexpectedKerberosError(
                        rep.krb_error.error_code.name, rep.krb_error.e_text
                    )
                else:
                    kdc_rep = rep.as_rep.kdc_rep
        else:
            logging.info("user {} doesn't need preauth!".format(self._username))
            # TODO - can we use simple key to decrypt?
            raise
            kdc_rep = rep.as_rep.kdc_rep

        # decrypt encrypted part of response
        # (https://www.ietf.org/archive/id/draft-ietf-kitten-krb-spake-preauth-12.html#section-4.5)
        # use K'[0]
        epart = EncRepPart.load(
            decrypt(k_0, KeyUsageType.AS_REP_ENCPART, kdc_rep.enc_part.cipher)
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
