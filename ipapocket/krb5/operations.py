from datetime import datetime, timezone, timedelta
import secrets
import logging
import collections
from ipapocket.krb5.objects import *
from ipapocket.krb5.constants import *
from ipapocket.krb5.crypto import crypto
from ipapocket.krb5.crypto.base import _get_etype_profile, Key
from ipapocket.exceptions.exceptions import NoSupportedEtypes
from ipapocket.krb5.asn1 import KrbErrorAsn1, PaDatasAsn1, EtypeInfo2Asn1, EtypeInfoAsn1


def as_req_wihtout_pa(domain: str, username: str) -> AsReq:
    """
    Create AS-REQ packet without Preauthentication data
    """
    # we need uppercase domain
    domain = domain.upper()
    # create UPN
    upn = PrincipalName(PrincipalType.NT_PRINCIPAL, username)
    # create realm
    realm = Realm(domain)
    # create sname
    server_name = PrincipalName(PrincipalType.NT_PRINCIPAL, ["krbtgt", domain])

    current_timestamp = datetime.now(timezone.utc)

    # create KDC request body
    kdc_req_body = KdcReqBody()

    # create KDC options
    kdc_options = KdcOptions()
    kdc_options.add(KdcOptionsTypes.FORWARDABLE)
    kdc_options.add(KdcOptionsTypes.CANONICALIZE)
    kdc_options.add(KdcOptionsTypes.RENEWABLE_OK)

    # generate timestamps for validatity of TGT (+1 day)
    till = KerberosTime(current_timestamp + timedelta(days=1))
    rtime = KerberosTime(current_timestamp + timedelta(days=1))

    # generate nonce
    nonce = UInt32(secrets.randbits(31))

    # set options in request
    kdc_req_body.kdc_options = kdc_options
    # set cname in request
    kdc_req_body.cname = upn
    # set realm in request
    kdc_req_body.realm = realm
    # set sname in request
    kdc_req_body.sname = server_name
    # set till in request
    kdc_req_body.till = till
    # set rtime in request
    kdc_req_body.rtime = rtime
    # set nonce in request
    kdc_req_body.nonce = nonce

    # set etype in request
    kdc_req_body.etype = EncTypes(crypto.supported_enctypes())

    # create KDC request
    kdc_req = KdcReq()

    # add version of kerberos
    kdc_req.pvno = KRB5_VERSION
    # add KDC requst body
    kdc_req.req_body = kdc_req_body
    # add message type
    kdc_req.msg_type = MessageTypes.KRB_AS_REQ

    # create AS-REQ
    return AsReq(kdc_req)


def _krb_key(etype: EncryptionTypes, password, salt) -> Key:
    return crypto.string_to_key(etype, password, salt)


def as_req_with_pa(
    domain: str, username: str, password: str, etype: collections.OrderedDict, salt
) -> AsReq:
    """
    Create AS-REQ packet with Preauthentication data
    """
    # we need uppercase domain
    domain = domain.upper()
    # create UPN
    username = PrincipalName(PrincipalType.NT_PRINCIPAL, username)
    # create realm
    realm = Realm(domain)
    # create sname
    server_name = PrincipalName(PrincipalType.NT_PRINCIPAL, ["krbtgt", domain])

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
    kdc_req_body.kdc_options = kdc_options
    # set cname in request
    kdc_req_body.cname = username
    # set realm in request
    kdc_req_body.realm = realm
    # set sname in request
    kdc_req_body.sname = server_name
    # set till in request
    kdc_req_body.till = till
    # set rtime in request
    kdc_req_body.rtime = rtime
    # set nonce in request
    kdc_req_body.nonce = nonce

    # set etype in request
    kdc_req_body.etype = EncTypes(crypto.supported_enctypes())

    # create KDC request
    kdc_req = KdcReq()

    # create encrypted PA-DATA
    pa_datas = PaDatas()
    pa_enc_ts = PaEncTsEnc(current_timestamp, current_timestamp.microsecond)
    krb_key = _krb_key(etype, password, salt)
    enc_ts = _get_etype_profile(etype).encrypt(
        krb_key,
        KeyUsageTypes.AS_REQ_PA_ENC_TIMESTAMP.value,
        pa_enc_ts.to_asn1().dump(),
        None,
    )
    pa_datas.add(
        PaData(
            PreAuthenticationDataTypes.PA_ENC_TIMESTAMP,
            EncryptedData(etype, KRB5_VERSION, enc_ts),
        )
    )

    # add version of kerberos
    kdc_req.pvno = KRB5_VERSION
    # add KDC requst body
    kdc_req.req_body = kdc_req_body
    # add message type
    kdc_req.msg_type = MessageTypes.KRB_AS_REQ
    # add pa data
    kdc_req.padata = pa_datas

    # create AS-REQ
    return AsReq(kdc_req)


def get_preferred_etype(krb_err: KrbErrorAsn1):
    # make it native
    krb_err = krb_err.native
    enc_methods = collections.OrderedDict()
    for method in PaDatasAsn1.load(krb_err["e-data"]).native:
        data_type = PreAuthenticationDataTypes(method["padata-type"])
        enc_list = list()
        if data_type == PreAuthenticationDataTypes.PA_ETYPE_INFO2:
            enc_list = EtypeInfo2Asn1.load(method["padata-value"])
        if data_type == PreAuthenticationDataTypes.PA_ETYPE_INFO:
            enc_list = EtypeInfoAsn1.load(method["padata-value"])
        for enc_entry in enc_list:
            enc_methods[EncryptionTypes(enc_entry["etype"].native)] = enc_entry["salt"]
            logging.debug(
                "Server support etype {} with salt {}".format(
                    EncryptionTypes(enc_entry["etype"].native).name, enc_entry["salt"]
                )
            )
    if len(enc_methods) == 0:
        raise NoSupportedEtypes("no supported server PA etypes exists in this client")
    for algo in crypto.supported_enctypes():
        # first algo will be accept (as it weaker)
        if algo in enc_methods:
            supported_etype = collections.OrderedDict()
            salt = enc_methods[algo]
            if salt is not None:
                salt = salt.native.encode()
            supported_etype[algo] = salt
            return algo, salt
        raise NoSupportedEtypes("no supported client etypes exists")
