import ipapocket.krb5.asn1 as asn1
from ipapocket.krb5.constants import *
from ipapocket.krb5.fields import *
from ipapocket.exceptions.krb5 import *
from datetime import datetime

# Int32
from ipapocket.krb5.types.int32 import Int32

# UInt32
from ipapocket.krb5.types.uint32 import UInt32

# Microseconds
from ipapocket.krb5.types.microseconds import Microseconds

# KerberosString
from ipapocket.krb5.types.kerberos_string import KerberosString

# KerberosStrings
from ipapocket.krb5.types.kerberos_strings import KerberosStrings

# PrincipalName
from ipapocket.krb5.types.principal_name import PrincipalName

# Realm
from ipapocket.krb5.types.realm import Realm

# KerberosFlags
from ipapocket.krb5.types.kerberos_flags import KerberosFlags

# KdcOptions
from ipapocket.krb5.types.kdc_options import KdcOptions

# TicketFlags
from ipapocket.krb5.types.ticket_flags import TicketFlags

# KerberosTime
from ipapocket.krb5.types.kerberos_time import KerberosTime

# EncTypes
from ipapocket.krb5.types.enc_types import EncTypes

# HostAddress
from ipapocket.krb5.types.host_address import HostAddress

# HostAddresses
from ipapocket.krb5.types.host_addresses import HostAddresses

# EncryptedData
from ipapocket.krb5.types.encrypted_data import EncryptedData

# Ticket
from ipapocket.krb5.types.ticket import Ticket

# Tickets
from ipapocket.krb5.types.tickets import Tickets

# KdcReqBody
from ipapocket.krb5.types.kdc_req_body import KdcReqBody

# PaEncTsEnc
from ipapocket.krb5.types.pa_enc_ts_enc import PaEncTsEnc

# EtypeInfoEntry
from ipapocket.krb5.types.etype_info_entry import EtypeInfoEntry

# EtypeInfo
from ipapocket.krb5.types.etype_info import EtypeInfo

# EtypeInfo2Entry
from ipapocket.krb5.types.etype_info2_entry import EtypeInfo2Entry

# EtypeInfo2
from ipapocket.krb5.types.etype_info2 import EtypeInfo2

# PaData
from ipapocket.krb5.types.pa_data import PaData

# MethodData
from ipapocket.krb5.types.method_data import MethodData

# KdcReq
from ipapocket.krb5.types.kdc_req import KdcReq

# AsReq
from ipapocket.krb5.types.as_req import AsReq

# TgsReq
from ipapocket.krb5.types.tgs_req import TgsReq

# KrbError
from ipapocket.krb5.types.krb_error import KrbError

# KdcRep
from ipapocket.krb5.types.kdc_rep import KdcRep

# UInt16
from ipapocket.krb5.types.uint16 import UInt16

# KrbSalt
from ipapocket.krb5.types.krb_salt import KrbSalt

# EncryptionKey
from ipapocket.krb5.types.encryption_key import EncryptionKey

# KrbKey
from ipapocket.krb5.types.krb_key import KrbKey

# KrbKeys
from ipapocket.krb5.types.krb_keys import KrbKeys

# KrbKeySet
from ipapocket.krb5.types.krb_key_set import KrbKeySet

# MasterKey
from ipapocket.krb5.types.master_key import MasterKey

# KrbMKey
from ipapocket.krb5.types.krb_mkey import KrbMKey


class AsRep:
    _kdc_rep: KdcRep = None

    def __init__(self, kdc_rep: KdcRep = None):
        self._kdc_rep = kdc_rep

    @property
    def kdc_rep(self) -> KdcRep:
        return self._kdc_rep

    @kdc_rep.setter
    def kdc_rep(self, value) -> None:
        self._kdc_rep = value

    @classmethod
    def load(cls, data: asn1.AsRepAsn1):
        if isinstance(data, AsRep):
            data = data.to_asn1()
        return cls(KdcRep.load(data))

    def to_asn1(self) -> asn1.AsRepAsn1:
        return asn1.AsRepAsn1(self._kdc_rep)

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()


class TgsRep:
    _kdc_rep: KdcRep = None

    def __init__(self, kdc_rep: KdcRep = None):
        self._kdc_rep = kdc_rep

    @property
    def kdc_rep(self) -> KdcRep:
        return self._kdc_rep

    @kdc_rep.setter
    def kdc_rep(self, value) -> None:
        self._kdc_rep = value

    @classmethod
    def load(cls, data: asn1.TgsRepAsn1):
        if isinstance(data, TgsRep):
            data = data.to_asn1()
        return cls(KdcRep.load(data))

    def to_asn1(self) -> asn1.TgsRepAsn1:
        return asn1.TgsRepAsn1(self._kdc_rep)

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()


class KerberosResponse:
    _krb_error: KrbError = None
    _as_rep: AsRep = None
    _tgs_rep: TgsRep = None

    def __init__(self):
        pass

    def is_krb_error(self) -> bool:
        return self._krb_error is not None

    def is_as_rep(self) -> bool:
        return self._as_rep is not None

    def is_tgs_rep(self) -> bool:
        return self._tgs_rep is not None

    @property
    def krb_error(self) -> KrbError:
        return self._krb_error

    @krb_error.setter
    def krb_error(self, value) -> None:
        self._krb_error = value

    @property
    def as_rep(self) -> AsRep:
        return self._as_rep

    @as_rep.setter
    def as_rep(self, value) -> None:
        self._as_rep = value

    @property
    def tgs_rep(self) -> TgsRep:
        return self._tgs_rep

    @tgs_rep.setter
    def tgs_rep(self, value) -> None:
        self._tgs_rep = value

    @classmethod
    def load(cls, data):
        if isinstance(data, bytes):
            response = asn1.KerberosResponseAsn1.load(data)
        if response.name == KERBEROS_RESPONSE_KRB_ERROR:
            tmp = cls()
            tmp.krb_error = KrbError.load(asn1.KrbErrorAsn1.load(data))
            return tmp
        elif response.name == KERBEROS_RESPONSE_AS_REP:
            tmp = cls()
            tmp.as_rep = AsRep.load(asn1.AsRepAsn1.load(data))
            return tmp
        elif response.name == KERBEROS_RESPONSE_TGS_REP:
            tmp = cls()
            tmp.tgs_rep = TgsRep.load(asn1.TgsRepAsn1.load(data))
            return tmp
        else:
            # unexpected response type
            raise UnexpectedResponseType(response.name)

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()


class LastReq:
    _lr_type: Int32 = None
    _lr_value: KerberosTime = None

    def __init__(self):
        pass

    @property
    def lr_type(self) -> Int32:
        return self._lr_type

    @lr_type.setter
    def lr_type(self, value) -> None:
        self._lr_type = value

    @property
    def lr_value(self) -> KerberosTime:
        return self._lr_value

    @lr_value.setter
    def lr_value(self, value) -> None:
        self._lr_value = value

    @classmethod
    def load(cls, data: asn1.LastReqAsn1):
        if isinstance(data, LastReq):
            data = data.to_asn1()
        tmp = cls()
        if LAST_REQ_LR_TYPE in data:
            if data[LAST_REQ_LR_TYPE].native is not None:
                tmp.lr_type = Int32.load(data[LAST_REQ_LR_TYPE])
        if LAST_REQ_LR_VALUE in data:
            if data[LAST_REQ_LR_VALUE].native is not None:
                tmp.lr_value = KerberosTime.load(data[LAST_REQ_LR_VALUE])
        return tmp

    def to_asn1(self) -> asn1.LastReqAsn1:
        last_req = asn1.LastReqAsn1()
        if self._lr_type is not None:
            last_req[LAST_REQ_LR_TYPE] = self._lr_type.to_asn1()
        if self._lr_value is not None:
            last_req[LAST_REQ_LR_VALUE] = self._lr_value.to_asn1()
        return last_req

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()


class LastReqs:
    _reqs: list[LastReq] = None

    def __init__(self):
        self._reqs = list()

    def add(self, value: LastReq):
        self._reqs.append(value)

    def clear(self):
        self._reqs = list()

    @classmethod
    def load(cls, data: asn1.LastReqsAsn1):
        if isinstance(data, LastReqs):
            data = data.to_asn1()
        tmp = cls()
        for v in data:
            tmp.add(LastReq.load(v))
        return tmp

    def to_asn1(self) -> asn1.LastReqsAsn1:
        tmp = list()
        for v in self._reqs:
            tmp.append(v.to_asn1())
        return asn1.LastReqsAsn1(tmp)

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()


class EncKdcRepPart:
    _key: EncryptionKey = None
    _last_req: LastReqs = None
    _nonce: UInt32 = None
    _key_expiration: KerberosTime = None
    _flags: TicketFlags = None
    _authtime: KerberosTime = None
    _starttime: KerberosTime = None
    _endtime: KerberosTime = None
    _renew_till: KerberosTime = None
    _srealm: Realm = None
    _sname: PrincipalName = None
    _caddr: HostAddresses = None

    def __init__(self):
        pass

    @property
    def key(self) -> EncryptionKey:
        return self._key

    @key.setter
    def key(self, value) -> None:
        self._key = value

    @property
    def last_req(self) -> LastReqs:
        return self._last_req

    @last_req.setter
    def last_req(self, value) -> None:
        self._last_req = value

    @property
    def nonce(self) -> UInt32:
        return self._nonce

    @nonce.setter
    def nonce(self, value) -> None:
        self._nonce = value

    @property
    def key_expiration(self) -> KerberosTime:
        return self._key_expiration

    @key_expiration.setter
    def key_expiration(self, value) -> None:
        self._key_expiration = value

    @property
    def flags(self) -> TicketFlags:
        return self._flags

    @flags.setter
    def flags(self, value) -> None:
        self._flags = value

    @property
    def authtime(self) -> KerberosTime:
        return self._authtime

    @authtime.setter
    def authtime(self, value) -> None:
        self._authtime = value

    @property
    def starttime(self) -> KerberosTime:
        return self._starttime

    @starttime.setter
    def starttime(self, value) -> None:
        self._starttime = value

    @property
    def endtime(self) -> KerberosTime:
        return self._endtime

    @endtime.setter
    def endtime(self, value) -> None:
        self._endtime = value

    @property
    def renew_till(self) -> KerberosTime:
        return self._renew_till

    @renew_till.setter
    def renew_till(self, value) -> None:
        self._renew_till = value

    @property
    def srealm(self) -> Realm:
        return self._srealm

    @srealm.setter
    def srealm(self, value) -> None:
        self._srealm = value

    @property
    def sname(self) -> PrincipalName:
        return self._sname

    @sname.setter
    def sname(self, value) -> None:
        self._sname = value

    @property
    def caddr(self) -> HostAddresses:
        return self._caddr

    @caddr.setter
    def caddr(self, value) -> None:
        self._caddr = value

    @classmethod
    def load(cls, data: asn1.EncKdcRepPartAsn1):
        if isinstance(data, EncKdcRepPart):
            data = data.to_asn1()
        tmp = cls()
        if ENC_KDC_REP_PART_KEY in data:
            if data[ENC_KDC_REP_PART_KEY].native is not None:
                tmp.key = EncryptionKey.load(data[ENC_KDC_REP_PART_KEY])
        if ENC_KDC_REP_PART_LAST_REQ in data:
            if data[ENC_KDC_REP_PART_LAST_REQ].native is not None:
                tmp.last_req = LastReqs.load(data[ENC_KDC_REP_PART_LAST_REQ])
        if ENC_KDC_REP_PART_NONCE in data:
            if data[ENC_KDC_REP_PART_NONCE].native is not None:
                tmp.nonce = UInt32.load(data[ENC_KDC_REP_PART_NONCE])
        if ENC_KDC_REP_PART_KEY_EXPIRATION in data:
            if data[ENC_KDC_REP_PART_KEY_EXPIRATION].native is not None:
                tmp.key_expiration = KerberosTime.load(
                    data[ENC_KDC_REP_PART_KEY_EXPIRATION]
                )
        if ENC_KDC_REP_PART_FLAGS in data:
            if data[ENC_KDC_REP_PART_FLAGS].native is not None:
                tmp.flags = TicketFlags.load(data[ENC_KDC_REP_PART_FLAGS])
        if ENC_KDC_REP_PART_AUTHTIME in data:
            if data[ENC_KDC_REP_PART_AUTHTIME].native is not None:
                tmp.authtime = KerberosTime.load(data[ENC_KDC_REP_PART_AUTHTIME])
        if ENC_KDC_REP_PART_STARTTIME in data:
            if data[ENC_KDC_REP_PART_STARTTIME].native is not None:
                tmp.starttime = KerberosTime.load(data[ENC_KDC_REP_PART_STARTTIME])
        if ENC_KDC_REP_PART_ENDTIME in data:
            if data[ENC_KDC_REP_PART_ENDTIME].native is not None:
                tmp.endtime = KerberosTime.load(data[ENC_KDC_REP_PART_ENDTIME])
        if ENC_KDC_REP_PART_RENEW_TILL in data:
            if data[ENC_KDC_REP_PART_RENEW_TILL].native is not None:
                tmp.renew_till = KerberosTime.load(data[ENC_KDC_REP_PART_RENEW_TILL])
        if ENC_KDC_REP_PART_SREALM in data:
            if data[ENC_KDC_REP_PART_SREALM].native is not None:
                tmp.srealm = Realm.load(data[ENC_KDC_REP_PART_SREALM])
        if ENC_KDC_REP_PART_SNAME in data:
            if data[ENC_KDC_REP_PART_SNAME].native is not None:
                tmp.sname = PrincipalName.load(data[ENC_KDC_REP_PART_SNAME])
        if ENC_KDC_REP_PART_CADDR in data:
            if data[ENC_KDC_REP_PART_CADDR].native is not None:
                tmp.caddr = HostAddresses.load(data[ENC_KDC_REP_PART_CADDR])
        return tmp

    def to_asn1(self) -> asn1.EncKdcRepPartAsn1:
        return asn1.EncKdcRepPartAsn1()

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()


class EncAsRepPart:
    _enc_kdc_rep_part: EncKdcRepPart = None

    def __init__(self, enc_kdc_rep: EncKdcRepPart = None):
        self._enc_kdc_rep_part = enc_kdc_rep

    @property
    def enc_kdc_rep_part(self) -> EncKdcRepPart:
        return self._enc_kdc_rep_part

    @enc_kdc_rep_part.setter
    def enc_kdc_rep_part(self, value) -> None:
        self._enc_kdc_rep_part = value

    @classmethod
    def load(cls, data: asn1.EncAsRepPartAsn1):
        if isinstance(data, bytes):
            data = asn1.EncAsRepPartAsn1.load(data)
        if isinstance(data, EncAsRepPart):
            data = data.to_asn1()
        return cls(EncKdcRepPart.load(data))

    def to_asn1(self) -> asn1.EncAsRepPartAsn1:
        return asn1.EncAsRepPartAsn1(self._enc_kdc_rep_part)

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()


class EncTgsRepPart:
    _enc_kdc_rep_part: EncKdcRepPart = None

    def __init__(self, enc_kdc_rep: EncKdcRepPart = None):
        self._enc_kdc_rep_part = enc_kdc_rep

    @property
    def enc_kdc_rep_part(self) -> EncKdcRepPart:
        return self._enc_kdc_rep_part

    @enc_kdc_rep_part.setter
    def enc_kdc_rep_part(self, value) -> None:
        self._enc_kdc_rep_part = value

    @classmethod
    def load(cls, data: asn1.EncTgsRepPartAsn1):
        if isinstance(data, bytes):
            data = asn1.EncTgsRepPartAsn1.load(data)
        if isinstance(data, EncTgsRepPart):
            data = data.to_asn1()
        return cls(EncKdcRepPart.load(data))

    def to_asn1(self) -> asn1.EncTgsRepPartAsn1:
        return asn1.EncTgsRepPartAsn1(self._enc_kdc_rep_part)

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()


class EncRepPart:
    _enc_as_rep_part: EncAsRepPart = None
    _enc_tgs_rep_part: EncTgsRepPart = None

    def __init__(self):
        pass

    def is_enc_as_rep(self) -> bool:
        return self._enc_as_rep_part is not None

    def is_enc_tgs_rep(self) -> bool:
        return self._enc_tgs_rep_part is not None

    @property
    def enc_as_rep_part(self) -> EncAsRepPart:
        return self._enc_as_rep_part

    @enc_as_rep_part.setter
    def enc_as_rep_part(self, value) -> None:
        self._enc_as_rep_part = value

    @property
    def enc_tgs_rep_part(self) -> EncTgsRepPart:
        return self._enc_tgs_rep_part

    @enc_tgs_rep_part.setter
    def enc_tgs_rep_part(self, value) -> None:
        self._enc_tgs_rep_part = value

    @classmethod
    def load(cls, data: asn1.EncRepPartAsn1):
        if isinstance(data, bytes):
            response = asn1.EncRepPartAsn1.load(data)
        if response.name == ENC_PART_REP_AS_REP:
            tmp = cls()
            tmp.enc_as_rep_part = EncAsRepPart.load(data)
            return tmp
        elif response.name == ENC_PART_REP_TGS_REP:
            tmp = cls()
            tmp.enc_tgs_rep_part = EncTgsRepPart.load(data)
            return tmp
        else:
            raise UnexpectedEncRepPartType()

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()


class ApOptions:
    _options: KerberosFlags = None

    def __init__(self):
        self._options = KerberosFlags()

    def add(self, option):
        self._options.add(self._validate_option(option))

    def clear(self):
        self._options.clear()

    @property
    def options(self):
        return self._options.flags

    @classmethod
    def load(cls, value: asn1.ApOptionsAsn1):
        if isinstance(value, ApOptions):
            value = value.to_asn1()
        tmp = cls()
        for v in value.native:
            if v == 1:
                tmp.add(ApOptionsTypes(v))
        return tmp

    def _validate_option(self, value) -> ApOptionsTypes:
        if not isinstance(value, ApOptionsTypes):
            raise InvalidApOptionsValueType(value)
        return value

    def to_asn1(self) -> asn1.ApOptionsAsn1:
        return asn1.ApOptionsAsn1(self._options.to_asn1().native)

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()


class Checksum:
    _cksumtype: ChecksumTypes = None
    _checksum: str = None

    def __init__(self):
        pass

    @property
    def cksumtype(self) -> ChecksumTypes:
        return self._cksumtype

    @cksumtype.setter
    def cksumtype(self, value) -> None:
        self._cksumtype = value

    @property
    def checksum(self) -> str:
        return self._checksum

    @checksum.setter
    def checksum(self, value) -> None:
        self._checksum = value

    def to_asn1(self) -> asn1.ChecksumAsn1:
        checksum = asn1.ChecksumAsn1()
        if self.cksumtype is not None:
            checksum[CHECKSUM_CKSUMTYPE] = self.cksumtype.value
        if self.checksum is not None:
            checksum[CHECKSUM_CHECKSUM] = self._checksum
        return checksum

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()


class AuthorizationDataElement:
    _ad_type: AuthorizationDataTypes = None
    _ad_data: str = None

    def __init__(self):
        pass

    @property
    def ad_type(self) -> AuthorizationDataTypes:
        return self._ad_type

    @ad_type.setter
    def ad_type(self, value) -> None:
        self._ad_type = value

    @property
    def ad_data(self) -> str:
        return self._ad_data

    @ad_data.setter
    def ad_data(self, value) -> None:
        self._ad_data = value

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()


class AuthorizationData:
    _elements: list[AuthorizationDataElement] = None

    def __init__(self):
        self._elements = list()

    def add(self, value):
        self._elements.append(value)

    @property
    def elements(self) -> list[AuthorizationDataElement]:
        return self._elements

    @classmethod
    def load(cls, data: asn1.AuthenticatorAsn1):
        if isinstance(data, AuthorizationData):
            data = data.to_asn1()
        tmp = cls()
        for v in data:
            tmp.add(AuthorizationDataElement.load(v))
        return tmp

    def to_asn1(self) -> asn1.AuthorizationDataAsn1:
        tmp = list()
        for v in self.elements:
            tmp.append(v.to_asn1())
        return asn1.AuthorizationDataAsn1(tmp)

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()


class Authenticator:
    _authenticator_vno: Int32 = None
    _crealm: Realm = None
    _cname: PrincipalName = None
    _cksum: Checksum = None
    _cusec: Microseconds = None
    _ctime: KerberosTime = None
    _subkey: EncryptionKey = None
    _seq_number: UInt32 = None
    _authorization_data: AuthorizationData = None

    @property
    def authenticator_vno(self) -> Int32:
        return self._authenticator_vno

    @authenticator_vno.setter
    def authenticator_vno(self, value) -> None:
        if isinstance(value, int):
            self._authenticator_vno = Int32.load(value)
        else:
            self._authenticator_vno = value

    @property
    def crealm(self) -> Realm:
        return self._crealm

    @crealm.setter
    def crealm(self, value) -> None:
        self._crealm = value

    @property
    def cname(self) -> PrincipalName:
        return self._cname

    @cname.setter
    def cname(self, value) -> None:
        self._cname = value

    @property
    def cksum(self) -> Checksum:
        return self._cksum

    @cksum.setter
    def cksum(self, value) -> None:
        self._cksum = value

    @property
    def cusec(self) -> Microseconds:
        return self._cusec

    @cusec.setter
    def cusec(self, value) -> None:
        self._cusec = value

    @property
    def ctime(self) -> KerberosTime:
        return self._ctime

    @ctime.setter
    def ctime(self, value) -> None:
        self._ctime = value

    @property
    def subkey(self) -> EncryptionKey:
        return self._subkey

    @subkey.setter
    def subkey(self, value) -> None:
        self._subkey = value

    @property
    def seq_number(self) -> UInt32:
        return self._seq_number

    @seq_number.setter
    def seq_number(self, value) -> None:
        if isinstance(value, int):
            self._seq_number = UInt32.load(value)
        else:
            self._seq_number = value

    @property
    def authorization_data(self) -> AuthorizationData:
        return self._authorization_data

    @authorization_data.setter
    def authorization_data(self, value) -> None:
        self._authorization_data = value

    @classmethod
    def load(cls, data: asn1.AuthenticatorAsn1):
        if isinstance(data, Authenticator):
            data = data.to_asn1()
        tmp = cls()
        if AUTHENTICATOR_AUTHENTICATOR_VNO in data:
            if data[AUTHENTICATOR_AUTHENTICATOR_VNO].native is not None:
                tmp.authenticator_vno = Int32.load(
                    data[AUTHENTICATOR_AUTHENTICATOR_VNO]
                )
        if AUTHENTICATOR_CREALM in data:
            if data[AUTHENTICATOR_CREALM].native is not None:
                tmp.crealm = Realm.load(data[AUTHENTICATOR_CREALM])
        if AUTHENTICATOR_CNAME in data:
            if data[AUTHENTICATOR_CNAME].native is not None:
                tmp.cname = PrincipalName.load(data[AUTHENTICATOR_CNAME])
        if AUTHENTICATOR_CKSUM in data:
            if data[AUTHENTICATOR_CKSUM].native is not None:
                tmp.cksum = Checksum.load(data[AUTHENTICATOR_CKSUM])
        if AUTHENTICATOR_CUSEC in data:
            if data[AUTHENTICATOR_CUSEC].native is not None:
                tmp.cusec = Microseconds.load(data[AUTHENTICATOR_CUSEC])
        if AUTHENTICATOR_CTIME in data:
            if data[AUTHENTICATOR_CTIME].native is not None:
                tmp.ctime = KerberosTime.load(data[AUTHENTICATOR_CTIME])
        if AUTHENTICATOR_SUBKEY in data:
            if data[AUTHENTICATOR_SUBKEY].native is not None:
                tmp.subkey = EncryptionKey.load(data[AUTHENTICATOR_SUBKEY])
        if AUTHENTICATOR_SEQ_NUMBER in data:
            if data[AUTHENTICATOR_SEQ_NUMBER].native is not None:
                tmp.seq_number = UInt32.load(data[AUTHENTICATOR_SEQ_NUMBER])
        if AUTHENTICATOR_AUTHORIZATION_DATA in data:
            if data[AUTHENTICATOR_AUTHORIZATION_DATA].native is not None:
                tmp.authorization_data = AuthorizationData.load(
                    data[AUTHENTICATOR_AUTHORIZATION_DATA]
                )
        return tmp

    def to_asn1(self) -> asn1.AuthenticatorAsn1:
        authenticator = asn1.AuthenticatorAsn1()
        if self.authenticator_vno is not None:
            authenticator[AUTHENTICATOR_AUTHENTICATOR_VNO] = (
                self.authenticator_vno.to_asn1()
            )
        if self.crealm is not None:
            authenticator[AUTHENTICATOR_CREALM] = self.crealm.to_asn1()
        if self.cname is not None:
            authenticator[AUTHENTICATOR_CNAME] = self.cname.to_asn1()
        if self.cksum is not None:
            authenticator[AUTHENTICATOR_CKSUM] = self.cksum.to_asn1()
        if self.cusec is not None:
            authenticator[AUTHENTICATOR_CUSEC] = self.cusec.to_asn1()
        if self.ctime is not None:
            authenticator[AUTHENTICATOR_CTIME] = self.ctime.to_asn1()
        if self.subkey is not None:
            authenticator[AUTHENTICATOR_SUBKEY] = self.subkey.to_asn1()
        if self.seq_number is not None:
            authenticator[AUTHENTICATOR_SEQ_NUMBER] = self.seq_number.to_asn1()
        if self.authorization_data is not None:
            authenticator[AUTHENTICATOR_AUTHORIZATION_DATA] = (
                self.authorization_data.to_asn1()
            )
        return authenticator

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()


class ApReq:
    _pvno: Int32 = None
    _msg_type: MessageTypes = None
    _ap_options: ApOptions = None
    _ticket: Ticket = None
    _authenticator: EncryptedData = None

    def __init__(self):
        pass

    @property
    def pvno(self) -> Int32:
        return self._pvno

    @pvno.setter
    def pvno(self, value) -> None:
        if isinstance(value, int):
            self._pvno = Int32.load(value)
        else:
            self._pvno = value

    @property
    def msg_type(self) -> MessageTypes:
        return self._msg_type

    @msg_type.setter
    def msg_type(self, value) -> None:
        self._msg_type = value

    @property
    def ap_options(self) -> ApOptions:
        return self._ap_options

    @ap_options.setter
    def ap_options(self, value) -> None:
        self._ap_options = value

    @property
    def ticket(self) -> Ticket:
        return self._ticket

    @ticket.setter
    def ticket(self, value) -> None:
        self._ticket = value

    @property
    def authenticator(self) -> EncryptedData:
        return self._authenticator

    @authenticator.setter
    def authenticator(self, value) -> None:
        self._authenticator = value

    @classmethod
    def load(cls, data: asn1.ApReqAsn1):
        if isinstance(data, ApReq):
            data = data.to_asn1()
        tmp = cls()
        if AP_REQ_PVNO in data:
            if data[AP_REQ_PVNO].native is not None:
                tmp.pvno = Int32.load(data[AP_REQ_PVNO])
        if AP_REQ_MSG_TYPE in data:
            if data[AP_REQ_MSG_TYPE].native is not None:
                tmp.msg_type = MessageTypes(data[AP_REQ_MSG_TYPE].native)
        if AP_REQ_AP_OPTIONS in data:
            if data[AP_REQ_AP_OPTIONS].native is not None:
                tmp.ap_options = ApOptions.load(data[AP_REQ_AP_OPTIONS])
        if AP_REQ_TICKET in data:
            if data[AP_REQ_TICKET].native is not None:
                tmp.ticket = Ticket.load(data[AP_REQ_TICKET])
        if AP_REQ_AUTHENTICATOR in data:
            if data[AP_REQ_AUTHENTICATOR].native is not None:
                tmp.authenticator = EncryptedData.load(data[AP_REQ_AUTHENTICATOR])
        return tmp

    def to_asn1(self) -> asn1.ApReqAsn1:
        ap_req = asn1.ApReqAsn1()
        if self.pvno is not None:
            ap_req[AP_REQ_PVNO] = self.pvno.to_asn1()
        if self.msg_type is not None:
            ap_req[AP_REQ_MSG_TYPE] = self.msg_type.value
        if self.ap_options is not None:
            ap_req[AP_REQ_AP_OPTIONS] = self.ap_options.to_asn1()
        if self.ticket is not None:
            ap_req[AP_REQ_TICKET] = self.ticket.to_asn1()
        if self.authenticator is not None:
            ap_req[AP_REQ_AUTHENTICATOR] = self.authenticator.to_asn1()
        return ap_req

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()
