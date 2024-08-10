import ipapocket.krb5.asn1 as asn1
from ipapocket.krb5.constants import *
from bitarray import bitarray
from ipapocket.krb5.fields import *
from ipapocket.exceptions.krb5 import *
from datetime import datetime


class Int32:
    _value: int = None

    def __init__(self, value: int):
        self._value = self._validate_value(value)

    @classmethod
    def load(cls, data: asn1.Int32Asn1):
        if isinstance(data, Int32):
            data = data.to_asn1()
        return cls(data.native)

    def _validate_value(self, value) -> int:
        if value is None:
            return None
        if isinstance(value, Int32):
            return value.value
        if isinstance(value, enum.Enum):
            value = value.value
        if not isinstance(value, int):
            raise InvalidInt32Value(value)
        if value not in range(-2147483648, 2147483647):
            raise InvalidInt32Value(value)
        return value

    @property
    def value(self) -> int:
        return self._value

    @value.setter
    def value(self, value: int) -> None:
        self._value = self._validate_value(value)

    def to_asn1(self) -> asn1.Int32Asn1:
        return asn1.Int32Asn1(self._value)


class UInt32:
    _value: int = None

    def __init__(self, value: int):
        self._value = self._validate_value(value)

    @classmethod
    def load(cls, data: asn1.UInt32Asn1):
        if isinstance(data, UInt32):
            data = data.to_asn1()
        return cls(data.native)

    def _validate_value(self, value) -> int:
        if value is None:
            return None
        if isinstance(value, UInt32):
            return value.value
        if isinstance(value, enum.Enum):
            value = value.value
        if not isinstance(value, int):
            raise InvalidUInt32Value(value)
        if value not in range(0, 4294967295):
            raise InvalidUInt32Value(value)
        return value

    @property
    def value(self) -> int:
        return self._value

    @value.setter
    def value(self, value: int) -> None:
        self._value = self._validate_value(value)

    def to_asn1(self) -> asn1.UInt32Asn1:
        return asn1.UInt32Asn1(self._value)


class Microseconds:
    _value: int = None

    def __init__(self, value: int):
        self._value = self._validate_value(value)

    @classmethod
    def load(cls, data: asn1.MicrosecondsAsn1):
        if isinstance(data, Microseconds):
            data = data.to_asn1()
        return cls(data.native)

    def _validate_value(self, value) -> int:
        if not isinstance(value, int):
            raise InvalidMicrosecondsValue(value)
        if value not in range(0, 999999):
            raise InvalidMicrosecondsValue(value)
        return value

    @property
    def value(self) -> int:
        return self._value

    @value.setter
    def value(self, value: int) -> None:
        self._value = self._validate_value(value)

    def to_asn1(self) -> asn1.MicrosecondsAsn1:
        return asn1.MicrosecondsAsn1(self._value)


class KerberosString:
    _value: str = None

    def __init__(self, value: str = None):
        self._value = self._validate_value(value)

    def _validate_value(self, value) -> str:
        if isinstance(value, str):
            return value
        elif isinstance(value, KerberosString):
            return value.to_asn1().native
        else:
            raise InvalidKerberosStringValue(value)

    @classmethod
    def load(cls, data: asn1.KerberosStringAsn1):
        if isinstance(data, KerberosString):
            data = data.to_asn1()
        return cls(data.native)

    @property
    def value(self) -> str:
        return self._value

    @value.setter
    def value(self, value) -> None:
        self._value = self._validate_value(value)

    def to_asn1(self) -> asn1.KerberosStringAsn1:
        return asn1.KerberosStringAsn1(self._value)


class KerberosStrings:
    _value: list = None

    def __init__(self, value=None):
        self._value = self._validate_value(value)

    @classmethod
    def load(cls, data: asn1.KerberosStringsAsn1):
        if isinstance(data, KerberosStrings):
            data = data.to_asn1()
        return cls(data.native)

    def _validate_value(self, value) -> list:
        if isinstance(value, str):
            return [KerberosString(value)]
        elif isinstance(value, list):
            tmp = list()
            for v in value:
                tmp.append(KerberosString(v))
            return tmp
        elif isinstance(value, KerberosString):
            return [value]
        elif isinstance(value, KerberosStrings):
            tmp = list()
            for v in value.to_asn1().native:
                tmp.append(KerberosString(v))
            return tmp
        else:
            raise InvalidKerberosStringsValue(value)

    def to_asn1(self) -> asn1.KerberosStringsAsn1:
        tmp = list()
        for v in self._value:
            tmp.append(v.to_asn1())
        return asn1.KerberosStringsAsn1(tmp)


class PrincipalName:
    _type: PrincipalType = None
    _value: KerberosStrings = None

    def __init__(self, type: PrincipalType = None, value=None):
        self._type = type
        self._value = self._validate_value(value)

    @classmethod
    def load(cls, data: asn1.PrincipalNameAsn1):
        if isinstance(data, PrincipalName):
            data = data.to_asn1()
        return cls(
            type=PrincipalType(data.native[PRINCIPAL_NAME_NAME_TYPE]),
            value=data.native[PRINCIPAL_NAME_NAME_STRING],
        )

    @property
    def name_type(self) -> PrincipalType:
        return self._type

    @property
    def name_value(self):
        return self._value

    @name_type.setter
    def name_type(self, type: PrincipalType) -> None:
        self._type = type

    @name_value.setter
    def name_value(self, value) -> None:
        self._value = self._validate_value(value)

    def _validate_value(self, value) -> KerberosStrings:
        return KerberosStrings(value)

    def to_asn1(self) -> asn1.PrincipalNameAsn1:
        principal_name = asn1.PrincipalNameAsn1()
        if self._type is not None:
            principal_name[PRINCIPAL_NAME_NAME_TYPE] = self._type.value
        if self._value is not None:
            principal_name[PRINCIPAL_NAME_NAME_STRING] = self._value.to_asn1()
        return principal_name


class Realm:
    _realm: KerberosString = None

    def __init__(self, realm: str | KerberosString = None):
        self._realm = self._validate_realm(realm)

    @classmethod
    def load(cls, data: asn1.RealmAsn1):
        if isinstance(data, Realm):
            data = data.to_asn1()
        return cls(realm=data.native)

    def _validate_realm(self, realm) -> KerberosString:
        if isinstance(realm, str):
            return KerberosString(realm)
        elif isinstance(realm, KerberosString):
            return realm
        else:
            raise InvalidRealmValue(realm)

    @property
    def realm(self) -> str:
        return self._realm

    @realm.setter
    def realm(self, realm) -> None:
        self._realm = self._validate_realm(realm)

    def to_asn1(self) -> asn1.RealmAsn1:
        return asn1.RealmAsn1(self._realm.to_asn1().native)


class KerberosFlags:
    _flags: list = None

    def __init__(self):
        self._flags = list()

    @property
    def flags(self) -> list:
        return self._flags

    def add(self, flag):
        self._flags.append(self._validate_flag(flag))

    def clear(self):
        self._flags = list()

    def _validate_flag(self, flag):
        if not isinstance(flag, enum.Enum):
            raise InvalidKerberosFlagsValueType(flag)
        return flag

    def to_asn1(self):
        b_arr = bitarray(32)
        for flag in self._flags:
            b_arr[flag.value] = 1
        return asn1.KerberosFlagsAsn1(tuple(b_arr.tolist()))


class KdcOptions:
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
    def load(cls, value: asn1.KdcOptionsAsn1):
        if isinstance(value, KdcOptions):
            value = value.to_asn1()
        tmp = cls()
        for v in value.native:
            if v == 1:
                tmp.add(KdcOptionsTypes(v))
        return tmp

    def _validate_option(self, value) -> KdcOptionsTypes:
        if not isinstance(value, KdcOptionsTypes):
            raise InvalidKdcOptionsValueType(value)
        return value

    def to_asn1(self) -> asn1.KdcOptionsAsn1:
        return asn1.KdcOptionsAsn1(self._options.to_asn1().native)


class TicketFlags:
    _flags: KerberosFlags = None

    def __init__(self):
        self._flags = KerberosFlags()

    def add(self, flag):
        self._flags.add(self._validate_option(flag))

    def clear(self):
        self._flags.clear()

    @property
    def flags(self):
        return self._flags.flags

    @classmethod
    def load(cls, value: asn1.TicketFlagsAsn1):
        if isinstance(value, TicketFlags):
            value = value.to_asn1()
        tmp = cls()
        for v in value.native:
            if v == 1:
                tmp.add(TicketFlagsTypes(v))
        return tmp

    def _validate_option(self, value) -> TicketFlagsTypes:
        if not isinstance(value, TicketFlagsTypes):
            raise InvalidTicketFlagsValueType(value)
        return value

    def to_asn1(self) -> asn1.TicketFlagsAsn1:
        return asn1.TicketFlagsAsn1(self._flags.to_asn1().native)


class KerberosTime:
    _time: datetime = None

    def __init__(self, ktime: datetime):
        self._time = self._validate_time(ktime)

    def _validate_time(self, ktime):
        if not isinstance(ktime, datetime):
            raise InvalidKerberosTimeValueType(ktime)
        # we must remove microseconds from time (RFC note)
        return ktime.replace(microsecond=0)

    @property
    def time(self) -> datetime:
        return self._time

    @time.setter
    def time(self, value) -> None:
        self._time = self._validate_time(value)

    @classmethod
    def load(cls, data: asn1.KerberosTimeAsn1):
        if isinstance(data, KerberosTime):
            data = data.to_asn1()
        return cls(data.native)

    def to_asn1(self) -> asn1.KerberosTimeAsn1:
        return asn1.KerberosTimeAsn1(self._time)


class EncTypes:
    _etypes: list[EncryptionTypes] = None

    def __init__(self, etypes: list[EncryptionTypes]):
        self._etypes = etypes

    def _validate_etypes(self, value):
        if isinstance(value, int):
            return [EncryptionTypes(value)]
        elif isinstance(value, list[EncryptionTypes]):
            return value
        elif isinstance(value, EncryptionTypes):
            return [value]
        else:
            raise InvalidEncTypesValueType(value)

    @classmethod
    def load(cls, data: asn1.EncTypesAsn1):
        if isinstance(data, EncTypes):
            data = data.to_asn1()
        tmp = list[EncryptionTypes]()
        for v in data.native:
            tmp.append(EncryptionTypes(v))
        return cls(tmp)

    @property
    def etypes(self) -> list[EncryptionTypes]:
        return self._etypes

    @etypes.setter
    def etypes(self, value) -> None:
        self._etypes = self._validate_etypes(value)

    def to_asn1(self) -> asn1.EncTypesAsn1:
        final = list()
        for t in self._etypes:
            final.append(t.value)
        return asn1.EncTypesAsn1(final)


# TODO
class HostAddress:
    _type: Int32 = None
    _address = None

    def __init__(self, type, address):
        self._type = type
        self._address = address

    def to_asn1(self) -> asn1.HostAddressAsn1:
        host_address = asn1.HostAddressAsn1()
        if self._type is not None:
            host_address[HOST_ADDRESS_ADDR_TYPE] = self._type.to_asn1()
        if self._address is not None:
            host_address[HOST_ADDRESS_ADDRESS] = self._address
        return host_address


# TODO
class HostAddresses:
    _addresses: list[HostAddress] = None

    def __init__(self, addresses):
        self._addresses = addresses

    def to_asn1(self) -> asn1.HostAddressesAsn1:
        tmp = list()
        for v in self._addresses:
            tmp.append(v.to_asn1())
        return asn1.HostAddressesAsn1(tmp)


class EncryptedData:
    _etype: Int32 = None
    _kvno: UInt32 = None
    _cipher = None

    def __init__(self, etype=None, kvno=None, cipher=None):
        self._etype = self._validate_etype(etype)
        self._kvno = self._validate_kvno(kvno)
        self._cipher = cipher

    def _validate_etype(self, value):
        return Int32(value)

    def _validate_kvno(self, value):
        return UInt32(value)

    @classmethod
    def load(cls, data: asn1.EncryptedDataAsn1):
        if isinstance(data, EncryptedData):
            data = data.to_asn1()
        tmp = cls()
        if ENCRYPTED_DATA_ETYPE in data:
            if data[ENCRYPTED_DATA_ETYPE].native is not None:
                tmp.etype = Int32.load(data[ENCRYPTED_DATA_ETYPE])
        if ENCRYPTED_DATA_KVNO in data:
            if data[ENCRYPTED_DATA_KVNO].native is not None:
                tmp.kvno = UInt32.load(data[ENCRYPTED_DATA_KVNO])
        if ENCRYPTED_DATA_CIPHER in data:
            tmp.cipher = data[ENCRYPTED_DATA_CIPHER].native
        return tmp

    @property
    def etype(self) -> Int32:
        return self._etype

    @etype.setter
    def etype(self, value) -> None:
        self._etype = self._validate_etype(value)

    @property
    def kvno(self) -> UInt32:
        return self._kvno

    @kvno.setter
    def kvno(self, value) -> None:
        self._kvno = self._validate_kvno(value)

    @property
    def cipher(self):
        return self._cipher

    @cipher.setter
    def cipher(self, value) -> None:
        self._cipher = value

    def to_asn1(self) -> asn1.EncryptedDataAsn1:
        enc_data = asn1.EncryptedDataAsn1()
        if self._etype is not None:
            enc_data[ENCRYPTED_DATA_ETYPE] = self._etype.to_asn1()
        if self._kvno is not None:
            enc_data[ENCRYPTED_DATA_KVNO] = self._kvno.to_asn1()
        if self._cipher is not None:
            enc_data[ENCRYPTED_DATA_CIPHER] = self._cipher
        return enc_data


# TODO
class Ticket:
    pass


# TODO
class Tickets:
    pass


class KdcReqBody:
    _kdc_options: KdcOptions = None
    _cname: PrincipalName = None
    _realm: Realm = None
    _sname: PrincipalName = None
    _from: KerberosTime = None
    _till: KerberosTime = None
    _rtime: KerberosTime = None
    _nonce: UInt32 = None
    _etype: EncTypes = None
    _addresses: HostAddresses = None
    _enc_authorization_data: EncryptedData = None
    _additional_tickets: Tickets = None

    def __init__(self):
        pass

    @property
    def kdc_options(self):
        return self._kdc_options

    @kdc_options.setter
    def kdc_options(self, value):
        if not isinstance(value, KdcOptions):
            raise InvalidTypeInKdcReqBody("kdc_options", value)
        self._kdc_options = value

    @property
    def cname(self):
        return self._cname

    @cname.setter
    def cname(self, value):
        if not isinstance(value, PrincipalName):
            raise InvalidTypeInKdcReqBody("cname", value)
        self._cname = value

    @property
    def realm(self) -> Realm:
        return self._realm

    @realm.setter
    def realm(self, value):
        if not isinstance(value, Realm):
            raise InvalidTypeInKdcReqBody("realm", value)
        self._realm = value

    @property
    def sname(self) -> PrincipalName:
        return self._sname

    @sname.setter
    def sname(self, value) -> None:
        if not isinstance(value, PrincipalName):
            raise InvalidTypeInKdcReqBody("sname", value)
        self._sname = value

    @property
    def from_k(self) -> KerberosTime:
        return self._from

    @from_k.setter
    def from_k(self, value) -> None:
        if not isinstance(value, KerberosTime):
            raise InvalidTypeInKdcReqBody("from", value)
        self._from = value

    @property
    def till(self) -> KerberosTime:
        return self._till

    @till.setter
    def till(self, value) -> None:
        if not isinstance(value, KerberosTime):
            raise InvalidTypeInKdcReqBody("till", value)
        self._till = value

    @property
    def rtime(self) -> KerberosTime:
        return self._rtime

    @rtime.setter
    def rtime(self, value) -> None:
        if not isinstance(value, KerberosTime):
            raise InvalidTypeInKdcReqBody("cname", value)
        self._rtime = value

    @property
    def nonce(self) -> UInt32:
        return self._nonce

    @nonce.setter
    def nonce(self, value) -> None:
        if not isinstance(value, UInt32):
            raise InvalidTypeInKdcReqBody("nonce", value)
        self._nonce = value

    @property
    def etype(self) -> EncTypes:
        return self._etype

    @etype.setter
    def etype(self, value) -> None:
        if not isinstance(value, EncTypes):
            raise InvalidTypeInKdcReqBody("etype", value)
        self._etype = value

    @property
    def addresses(self) -> HostAddresses:
        return self._addresses

    @addresses.setter
    def addresses(self, value) -> None:
        if not isinstance(value, HostAddresses):
            raise InvalidTypeInKdcReqBody("addresses", value)
        self._addresses = value

    @property
    def enc_authorization_data(self) -> EncryptedData:
        return self._enc_authorization_data

    @enc_authorization_data.setter
    def enc_authorization_data(self, value) -> None:
        if not isinstance(value, EncryptedData):
            raise InvalidTypeInKdcReqBody("enc_authorization_data", value)
        self._enc_authorization_data = value

    @property
    def additional_tickets(self) -> Tickets:
        return self._additional_tickets

    @additional_tickets.setter
    def additional_tickets(self, value) -> None:
        if not isinstance(value, Tickets):
            raise InvalidTypeInKdcReqBody("additional_tickets", value)
        self._additional_tickets = value

    @classmethod
    def load(cls, data: asn1.KdcReqBodyAsn1):
        if isinstance(data, KdcReqBody):
            data = data.to_asn1()
        tmp = cls()
        if KDC_REQ_BODY_KDC_OPTIONS in data:
            if data[KDC_REQ_BODY_KDC_OPTIONS].native is not None:
                tmp.kdc_options = KdcOptions.load(data[KDC_REQ_BODY_KDC_OPTIONS])
        if KDC_REQ_BODY_CNAME in data:
            if data[KDC_REQ_BODY_CNAME].native is not None:
                tmp.cname = PrincipalName.load(data[KDC_REQ_BODY_CNAME])
        if KDC_REQ_BODY_REALM in data:
            if data[KDC_REQ_BODY_REALM].native is not None:
                tmp.realm = Realm.load(data[KDC_REQ_BODY_REALM])
        if KDC_REQ_BODY_SNAME in data:
            if data[KDC_REQ_BODY_SNAME].native is not None:
                tmp.sname = PrincipalName.load(data[KDC_REQ_BODY_SNAME])
        if KDC_REQ_BODY_FROM in data:
            if data[KDC_REQ_BODY_FROM].native is not None:
                tmp.from_k = KerberosTime.load(data[KDC_REQ_BODY_FROM])
        if KDC_REQ_BODY_TILL in data:
            if data[KDC_REQ_BODY_TILL].native is not None:
                tmp.till = KerberosTime.load(data[KDC_REQ_BODY_TILL])
        if KDC_REQ_BODY_RTIME in data:
            if data[KDC_REQ_BODY_RTIME].native is not None:
                tmp.rtime = KerberosTime.load(data[KDC_REQ_BODY_RTIME])
        if KDC_REQ_BODY_NONCE in data:
            if data[KDC_REQ_BODY_NONCE].native is not None:
                tmp.nonce = UInt32.load(data[KDC_REQ_BODY_NONCE])
        if KDC_REQ_BODY_ETYPE in data:
            if data[KDC_REQ_BODY_ETYPE].native is not None:
                tmp.etype = EncTypes.load(data[KDC_REQ_BODY_ETYPE])
        if KDC_REQ_BODY_ADDRESSES in data:
            if data[KDC_REQ_BODY_ADDRESSES].native is not None:
                tmp.addresses = HostAddresses.load(data[KDC_REQ_BODY_ADDRESSES])
        if KDC_REQ_BODY_ENC_AUTH_DATA in data:
            if data[KDC_REQ_BODY_ENC_AUTH_DATA].native is not None:
                tmp.enc_authorization_data = EncryptedData.load(
                    data[KDC_REQ_BODY_ENC_AUTH_DATA]
                )
        if KDC_REQ_BODY_ADDITIONAL_TICKETS in data:
            if data[KDC_REQ_BODY_ADDITIONAL_TICKETS].native is not None:
                tmp.additional_tickets = Tickets.load(
                    data[KDC_REQ_BODY_ADDITIONAL_TICKETS]
                )
        return tmp

    def to_asn1(self):
        kdc_req_body = asn1.KdcReqBodyAsn1()
        if self._kdc_options is not None:
            kdc_req_body[KDC_REQ_BODY_KDC_OPTIONS] = self._kdc_options.to_asn1()
        if self._cname is not None:
            kdc_req_body[KDC_REQ_BODY_CNAME] = self._cname.to_asn1()
        if self._realm is not None:
            kdc_req_body[KDC_REQ_BODY_REALM] = self._realm.to_asn1()
        if self._sname is not None:
            kdc_req_body[KDC_REQ_BODY_SNAME] = self._sname.to_asn1()
        if self._from is not None:
            kdc_req_body[KDC_REQ_BODY_FROM] = self._from.to_asn1()
        if self._till is not None:
            kdc_req_body[KDC_REQ_BODY_TILL] = self._till.to_asn1()
        if self._rtime is not None:
            kdc_req_body[KDC_REQ_BODY_RTIME] = self._rtime.to_asn1()
        if self._nonce is not None:
            kdc_req_body[KDC_REQ_BODY_NONCE] = self._nonce.to_asn1()
        if self._etype is not None:
            kdc_req_body[KDC_REQ_BODY_ETYPE] = self._etype.to_asn1()
        if self._addresses is not None:
            kdc_req_body[KDC_REQ_BODY_ADDRESSES] = self._addresses.to_asn1()
        if self._enc_authorization_data is not None:
            kdc_req_body[KDC_REQ_BODY_ENC_AUTH_DATA] = (
                self._enc_authorization_data.to_asn1()
            )
        if self._additional_tickets is not None:
            kdc_req_body[KDC_REQ_BODY_ADDITIONAL_TICKETS] = (
                self._additional_tickets.to_asn1()
            )
        return kdc_req_body


class PaEncTsEnc:
    _patimestamp: KerberosTime = None
    _pausec: Microseconds = None

    def __init__(self, timestamp=None, micros=None):
        self._patimestamp = self._validate_patimestamp(timestamp)
        self._pausec = self._validate_pausec(micros)

    def _validate_patimestamp(self, value):
        if value is None:
            return None
        if isinstance(value, datetime):
            return KerberosTime(value)
        elif isinstance(value, KerberosTime):
            return value
        else:
            raise InvalidPaEncTsEncPatimestamp()

    def _validate_pausec(self, value):
        if value is None:
            return None
        if isinstance(value, int):
            return Microseconds(value)
        elif isinstance(value, Microseconds):
            return value
        else:
            raise InvalidPaEncTsEncPausec()

    @property
    def patimestamp(self) -> KerberosTime:
        return self._patimestamp

    @patimestamp.setter
    def patimestamp(self, value) -> None:
        self._patimestamp = self._validate_patimestamp(value)

    @property
    def pausec(self) -> Microseconds:
        return self._pausec

    @pausec.setter
    def pausec(self, value) -> None:
        self._pausec = self._validate_pausec(value)

    @classmethod
    def load(cls, data: asn1.PaEncTsEncAsn1):
        if isinstance(data, PaEncTsEnc):
            data = data.to_asn1()
        tmp = cls()
        if PA_ENC_TS_ENC_PA_TIMESTAMP in data:
            if data[PA_ENC_TS_ENC_PA_TIMESTAMP].native is not None:
                tmp.patimestamp = KerberosTime.load(data[PA_ENC_TS_ENC_PA_TIMESTAMP])
        if PA_ENC_TS_ENC_PA_USEC in data:
            if data[PA_ENC_TS_ENC_PA_USEC].native is not None:
                tmp.pausec = Microseconds.load(data[PA_ENC_TS_ENC_PA_USEC])
        return tmp

    def to_asn1(self):
        pa_enc_ts_enc = asn1.PaEncTsEncAsn1()
        if self._patimestamp is not None:
            pa_enc_ts_enc[PA_ENC_TS_ENC_PA_TIMESTAMP] = self._patimestamp.to_asn1()
        if self._pausec is not None:
            pa_enc_ts_enc[PA_ENC_TS_ENC_PA_USEC] = self._pausec.to_asn1()
        return pa_enc_ts_enc


class PaData:
    _type: PreAuthenticationDataTypes = None
    _value = None

    def __init__(self, type=None, value=None):
        self._type = type
        self._value = self._validate_value(value)

    @property
    def type(self) -> PreAuthenticationDataTypes:
        return self._type

    @type.setter
    def type(self, value) -> None:
        if not isinstance(value, PreAuthenticationDataTypes):
            raise InvalidPaDataType()
        self._type = value

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, value):
        self._value = self._validate_value(value)

    def _validate_value(self, value):
        if isinstance(value, EncryptedData):
            return value.to_asn1().dump()
        else:
            return value

    @classmethod
    def load(cls, data: asn1.PaDataAsn1):
        if isinstance(data, PaData):
            data = data.to_asn1()
        tmp = cls()
        if PADATA_PADATA_TYPE in data:
            if data[PADATA_PADATA_TYPE] is not None:
                tmp.type = PreAuthenticationDataTypes(data[PADATA_PADATA_TYPE])
        if PADATA_PADATA_VALUE in data:
            if data[PADATA_PADATA_VALUE] is not None:
                tmp.value = data[PADATA_PADATA_VALUE]
        return tmp

    def to_asn1(self) -> asn1.PaDataAsn1:
        pa_data = asn1.PaDataAsn1()
        if self._type is not None:
            pa_data[PADATA_PADATA_TYPE] = self._type.value
        if self._value is not None:
            pa_data[PADATA_PADATA_VALUE] = self._value
        return pa_data


class PaDatas:
    _padatas: list = None

    def __init__(self):
        self._padatas = list()

    def add(self, padata):
        if not isinstance(padata, PaData):
            raise InvalidEncTypesValueType()
        self._padatas.append(padata)

    def clear(self):
        self._padatas = list()

    @classmethod
    def load(cls, data: asn1.PaDatasAsn1):
        if isinstance(data, PaDatas):
            data = data.to_asn1()
        tmp = cls()
        for v in data.native:
            tmp.add(PaData.load(v))
        return tmp

    def to_asn1(self):
        tmp = list()
        for pa_data in self._padatas:
            tmp.append(pa_data.to_asn1())
        return asn1.PaDatasAsn1(tuple(tmp))


class KdcReq:
    _pvno: Int32 = None
    _msg_type: MessageTypes = None
    _padata: PaDatas = None
    _req_body: KdcReqBody = None

    def __init__(self):
        pass

    @property
    def pvno(self) -> Int32:
        return self._pvno

    @pvno.setter
    def pvno(self, value) -> None:
        if isinstance(value, int):
            self._pvno = Int32(value)
        elif isinstance(value, Int32):
            self._pvno = value
        else:
            raise InvalidTypeInKdcReq(KDC_REQ_PVNO, value)

    @property
    def msg_type(self) -> Int32:
        return self._msg_type

    @msg_type.setter
    def msg_type(self, value) -> None:
        if isinstance(value, MessageTypes):
            self._msg_type = value
        elif isinstance(value, int):
            self._msg_type = MessageTypes(value)
        else:
            raise InvalidTypeInKdcReq(KDC_REQ_MSG_TYPE, value)

    @property
    def padata(self) -> PaDatas:
        return self._padata

    @padata.setter
    def padata(self, value) -> None:
        if not isinstance(value, PaDatas):
            raise InvalidTypeInKdcReq(KDC_REQ_PADATA, value)
        self._padata = value

    @property
    def req_body(self) -> KdcReqBody:
        return self._req_body

    @req_body.setter
    def req_body(self, value) -> None:
        if not isinstance(value, KdcReqBody):
            raise InvalidEncTypesValueType(KDC_REQ_REQ_BODY, value)
        self._req_body = value

    @classmethod
    def load(cls, data: asn1.KdcReqAsn1):
        if isinstance(data, KdcReq):
            data = data.to_asn1()
        tmp = cls()
        if KDC_REQ_PVNO in data:
            if data[KDC_REQ_PVNO].native is not None:
                tmp.pvno = Int32.load(data[KDC_REQ_PVNO])
        if KDC_REQ_MSG_TYPE in data:
            if data[KDC_REQ_MSG_TYPE].native is not None:
                tmp.msg_type = MessageTypes(data[KDC_REQ_MSG_TYPE].native)
        if KDC_REQ_PADATA in data:
            if data[KDC_REQ_PADATA].native is not None:
                tmp.padata = PaDatas.load(data[KDC_REQ_PADATA])
        if KDC_REQ_REQ_BODY in data:
            if data[KDC_REQ_REQ_BODY].native is not None:
                tmp.req_body = KdcReqBody.load(data[KDC_REQ_REQ_BODY])
        return tmp

    def to_asn1(self):
        kdc_req = asn1.KdcReqAsn1()
        if self._pvno is not None:
            kdc_req[KDC_REQ_PVNO] = self._pvno.to_asn1()
        if self._msg_type is not None:
            kdc_req[KDC_REQ_MSG_TYPE] = self._msg_type.value
        if self._req_body is not None:
            kdc_req[KDC_REQ_REQ_BODY] = self._req_body.to_asn1()
        if self._padata is not None:
            kdc_req[KDC_REQ_PADATA] = self._padata.to_asn1()
        return kdc_req


class AsReq:
    _req: KdcReq = None

    def __init__(self, req=None):
        self._req = self._validate_req(req)

    @property
    def req(self) -> KdcReq:
        return self._req

    @req.setter
    def req(self, value) -> None:
        self._req = self._validate_req(value)

    def _validate_req(self, req):
        if isinstance(req, KdcReq):
            return req
        else:
            raise InvalidAsReqRequest()

    @classmethod
    def load(cls, data: asn1.AsReqAsn1):
        if isinstance(data, AsReq):
            data = data.to_asn1()
        return cls(KdcReq.load(data))

    def to_asn1(self):
        return asn1.AsReqAsn1(self._req.to_asn1().native)
