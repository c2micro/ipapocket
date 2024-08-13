from datetime import datetime, timezone, timedelta
import secrets
import logging
import collections
from ipapocket.krb5.objects import *
from ipapocket.krb5.constants import *
from ipapocket.krb5.crypto import crypto
from ipapocket.krb5.crypto.base import _get_etype_profile, Key
from ipapocket.exceptions.exceptions import NoSupportedEtypes


class BaseKrb5Operations:
    _domain: str = None
    _username: str = None
    _password: str = None
    _etype: EncryptionTypes = None  # preferred type of etype
    _salt: str = None  # salt from PA
    _key: Key = None  # kerberos key

    def __init__(self, domain: str = None, username: str = None, password: str = None):
        self.domain = domain
        self.username = username
        self.password = password

    @property
    def domain(self) -> str:
        return self._domain

    @domain.setter
    def domain(self, value) -> None:
        self._domain = value

    @property
    def username(self) -> str:
        return self._username

    @username.setter
    def username(self, value) -> None:
        self._username = value

    @property
    def password(self) -> str:
        return self._password

    @password.setter
    def password(self, value) -> None:
        self._password = value

    @property
    def etype(self) -> EncryptionTypes:
        return self._etype

    @etype.setter
    def etype(self, value) -> None:
        self._etype = value

    @property
    def salt(self) -> str:
        return self._salt

    @salt.setter
    def salt(self, value) -> None:
        self._salt = value

    @property
    def key(self) -> Key:
        return self._key

    @key.setter
    def key(self, value) -> None:
        self._key = value

    def as_req_without_pa(self, username=None) -> AsReq:
        """
        Construct AS-REQ packet without encrypted Preauthentication Data
        """
        if username is not None:
            self.username = username

        current_timestamp = datetime.now(timezone.utc)
        # generate nonce
        nonce = UInt32(secrets.randbits(31))

        # need uppercase domain name
        domain = self.domain.upper()
        # cname (upn)
        cname = PrincipalName(PrincipalType.NT_PRINCIPAL, self.username)
        # realm
        realm = Realm(domain)
        # sname
        sname = PrincipalName(PrincipalType.NT_PRINCIPAL, ["krbtgt", domain])

        # KDC request body
        kdc_req_body = KdcReqBody()
        # KDC options (flags)
        kdc_options = KdcOptions()
        kdc_options.add(KdcOptionsTypes.FORWARDABLE)
        kdc_options.add(KdcOptionsTypes.CANONICALIZE)
        kdc_options.add(KdcOptionsTypes.RENEWABLE_OK)

        # create timestamps
        till = KerberosTime(current_timestamp + timedelta(days=1))
        rtime = KerberosTime(current_timestamp + timedelta(days=1))

        # set kdc options in body
        kdc_req_body.kdc_options = kdc_options
        # set cname in body
        kdc_req_body.cname = cname
        # set realm in body
        kdc_req_body.realm = realm
        # set sname in body
        kdc_req_body.sname = sname
        # set till timestamp in body
        kdc_req_body.till = till
        # set rtime timestamp in body
        kdc_req_body.rtime = rtime
        # set nonce in body
        kdc_req_body.nonce = nonce
        # set etype in body
        kdc_req_body.etype = EncTypes(crypto.supported_enctypes())

        # create KDC request
        kdc_req = KdcReq()

        # set version
        kdc_req.pvno = KRB5_VERSION
        # add request body
        kdc_req.req_body = kdc_req_body
        # add message type
        kdc_req.msg_type = MessageTypes.KRB_AS_REQ

        # create AS-REQ
        as_req = AsReq(kdc_req)

        return as_req

    def gen_key(self):
        """
        Generate user secret (kerberos key) based on algorithm, password and salt
        """
        self.key = crypto.string_to_key(self.etype, self.password, self.salt)

    def as_req_with_pa(self) -> AsReq:
        """
        Construct AS-REQ packet with encrypted Preauthentication Data
        """
        current_timestamp = datetime.now(timezone.utc)
        # generate nonce
        nonce = UInt32(secrets.randbits(31))

        # we need uppercase domain
        domain = self.domain.upper()
        # create cname
        cname = PrincipalName(PrincipalType.NT_PRINCIPAL, self.username)
        # create realm
        realm = Realm(domain)
        # create sname
        sname = PrincipalName(PrincipalType.NT_PRINCIPAL, ["krbtgt", domain])

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

        # set options in request
        kdc_req_body.kdc_options = kdc_options
        # set cname in request
        kdc_req_body.cname = cname
        # set realm in request
        kdc_req_body.realm = realm
        # set sname in request
        kdc_req_body.sname = sname
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

        enc_ts = _get_etype_profile(self.etype).encrypt(
            self.key,
            KeyUsageTypes.AS_REQ_PA_ENC_TIMESTAMP.value,
            pa_enc_ts.to_asn1().dump(),
            None,
        )
        pa_datas.add(
            PaData(
                PreAuthenticationDataTypes.PA_ENC_TIMESTAMP,
                EncryptedData(self.etype, KRB5_VERSION, enc_ts),
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
        as_req = AsReq(kdc_req)
        return as_req

    def as_req_preffered_etype(self, error: KrbError):
        """
        Iterate over array of proposed PA types from weak to strong
        """
        for padata in PaDatas.load(error.e_data).padatas:
            # from https://www.rfc-editor.org/rfc/rfc4120#section-5.2.7.5 - might be ONLY ONE ETYPE-ENTRY in sequence of each
            if padata.type == PreAuthenticationDataTypes.PA_ETYPE_INFO:
                etypes = EtypeInfo.load(padata.value)
                for etype in etypes._entries:
                    if etype.etype in crypto.supported_enctypes():
                        logging.debug(
                            "server support ETYPE-INFO with etype {} and salt {}".format(
                                etype.etype.name, etype.salt
                            )
                        )
                        # suppose that salt can't be null in this case
                        self.etype = etype.etype
                        self.salt = etype.salt
                        return
            if padata.type == PreAuthenticationDataTypes.PA_ETYPE_INFO2:
                etypes2 = EtypeInfo2.load(padata.value)
                for etype2 in etypes2._entries:
                    if etype2.etype in crypto.supported_enctypes():
                        logging.debug(
                            "server support ETYPE-INFO2 with etype {} and salt {}".format(
                                etype2.etype.name, etype2.salt.to_asn1().native
                            )
                        )
                        # suppose that salt can't be null in this case
                        self.etype = etype2.etype
                        self.salt = etype2.salt.to_asn1().native.encode()
                        return
        raise NoSupportedEtypes("no supported server PA etypes exists in this client")
