import ipapocket.krb5.asn1 as asn1
from ipapocket.krb5.constants import *
from bitarray import bitarray
from ipapocket.krb5.fields import *
from ipapocket.exceptions.krb5 import *
from datetime import datetime


class Int32:
    _value: int = 0

    def __init__(self, value=None):
        self.value = value

    @classmethod
    def load(cls, data: asn1.Int32Asn1):
        if isinstance(data, Int32):
            data = data.to_asn1()
        if isinstance(data, int):
            return cls(data)
        return cls(data.native)

    def _validate_value(self, value) -> int:
        if value is None:
            return 0
        if isinstance(value, Int32):
            return value.value
        if isinstance(value, enum.Enum):
            value = value.value
        if not isinstance(value, int):
            raise InvalidInt32Value(value)
        if value not in range(MIN_INT32, MAX_INT32 + 1):
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
    _value: int = 0

    def __init__(self, value=None):
        self.value = value

    @classmethod
    def load(cls, data: asn1.UInt32Asn1):
        if isinstance(data, UInt32):
            data = data.to_asn1()
        if isinstance(data, int):
            return cls(data)
        return cls(data.native)

    def _validate_value(self, value) -> int:
        if value is None:
            return 0
        if isinstance(value, UInt32):
            return value.value
        if isinstance(value, enum.Enum):
            value = value.value
        if not isinstance(value, int):
            raise InvalidUInt32Value(value)
        if value not in range(MIN_UINT32, MAX_UINT32 + 1):
            raise InvalidUInt32Value(value)
        return value

    @property
    def value(self) -> int:
        return self._value

    @value.setter
    def value(self, value) -> None:
        self._value = self._validate_value(value)

    def to_asn1(self) -> asn1.UInt32Asn1:
        return asn1.UInt32Asn1(self._value)


class Microseconds:
    _value: int = 0

    def __init__(self, value = None):
        self.value = value

    @classmethod
    def load(cls, data: asn1.MicrosecondsAsn1):
        if isinstance(data, Microseconds):
            data = data.to_asn1()
        if isinstance(data, int):
            return cls(data)
        return cls(data.native)

    def _validate_value(self, value) -> int:
        if value is None:
            value = 0
        if isinstance(value, Microseconds):
            return value.value
        if not isinstance(value, int):
            raise InvalidMicrosecondsValue(value)
        if value not in range(MIN_MICROSECONDS, MAX_MICROSECONDS + 1):
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

    def __init__(self, value=None):
        self.value = value

    def _validate_value(self, value) -> str:
        if value is None:
            return b""
        elif isinstance(value, str):
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


class HostAddress:
    _type: Int32 = None
    _address = None

    def __init__(self, type=None, address=None):
        self._type = type
        self._address = address

    @property
    def type(self) -> Int32:
        return self._type

    @type.setter
    def type(self, value) -> None:
        self._type = value

    @property
    def address(self):
        return self._address

    @address.setter
    def address(self, value) -> None:
        self._address = value

    @classmethod
    def load(cls, data: asn1.HostAddressAsn1):
        if isinstance(data, HostAddress):
            data = data.to_asn1()
        tmp = cls()
        if HOST_ADDRESS_ADDR_TYPE in data:
            if data[HOST_ADDRESS_ADDR_TYPE].native is not None:
                tmp.type = Int32.load(data[HOST_ADDRESS_ADDR_TYPE])
        if HOST_ADDRESS_ADDRESS in data:
            if data[HOST_ADDRESS_ADDRESS].native is not None:
                tmp.address = data[HOST_ADDRESS_ADDRESS].native
        return tmp

    def to_asn1(self) -> asn1.HostAddressAsn1:
        host_address = asn1.HostAddressAsn1()
        if self._type is not None:
            host_address[HOST_ADDRESS_ADDR_TYPE] = self._type.to_asn1()
        if self._address is not None:
            host_address[HOST_ADDRESS_ADDRESS] = self._address
        return host_address


class HostAddresses:
    _addresses: list[HostAddress] = None

    def __init__(self):
        self._addresses = list()

    def add(self, value):
        self._addresses.append(value)

    def clear(self):
        self._addresses = list()

    @classmethod
    def load(cls, data: asn1.HostAddressesAsn1):
        if isinstance(data, HostAddresses):
            data = data.to_asn1()
        tmp = cls()
        for v in data:
            tmp.add(HostAddress.load(v))
        return tmp

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


class Ticket:
    _tkt_vno: Int32 = None
    _realm: Realm = None
    _sname: PrincipalName = None
    _enc_part: EncryptedData = None

    def __init__(self):
        pass

    @property
    def tkt_vno(self) -> Int32:
        return self._tkt_vno

    @tkt_vno.setter
    def tkt_vno(self, value) -> None:
        self._tkt_vno = value

    @property
    def realm(self) -> Realm:
        return self._realm

    @realm.setter
    def realm(self, value) -> None:
        self._realm = value

    @property
    def sname(self) -> PrincipalName:
        return self._sname

    @sname.setter
    def sname(self, value) -> None:
        self._sname = value

    @property
    def enc_part(self) -> EncryptedData:
        return self._enc_part

    @enc_part.setter
    def enc_part(self, value) -> None:
        self._enc_part = value

    @classmethod
    def load(cls, data: asn1.TicketAsn1):
        if isinstance(data, Ticket):
            data = data.to_asn1()
        tmp = cls()
        if TICKET_TKT_VNO in data:
            if data[TICKET_TKT_VNO].native is not None:
                tmp.tkt_vno = Int32.load(data[TICKET_TKT_VNO])
        if TICKET_REALM in data:
            if data[TICKET_REALM].native is not None:
                tmp.realm = Realm.load(data[TICKET_REALM])
        if TICKET_SNAME in data:
            if data[TICKET_SNAME].native is not None:
                tmp.sname = PrincipalName.load(data[TICKET_SNAME])
        if TICKET_ENC_PART in data:
            if data[TICKET_ENC_PART].native is not None:
                tmp.enc_part = EncryptedData.load(data[TICKET_ENC_PART])
        return tmp

    def to_asn1(self) -> asn1.TicketAsn1:
        ticket = asn1.TicketAsn1()
        if self._tkt_vno is not None:
            ticket[TICKET_TKT_VNO] = self._tkt_vno.to_asn1()
        if self._realm is not None:
            ticket[TICKET_REALM] = self._realm.to_asn1()
        if self._sname is not None:
            ticket[TICKET_SNAME] = self._sname.to_asn1()
        if self._enc_part is not None:
            ticket[TICKET_ENC_PART] = self._enc_part.to_asn1()
        return ticket


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


class EtypeInfoEntry:
    _etype: EncryptionTypes = None
    _salt: str = None

    def __init__(self):
        pass

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

    @classmethod
    def load(cls, data: asn1.EtypeInfoEntryAsn1):
        if isinstance(data, bytes):
            data = asn1.EtypeInfoEntryAsn1.load(data)
        if isinstance(data, EtypeInfoEntry):
            data = data.to_asn1()
        tmp = cls()
        if ETYPE_INFO2_ETYPE in data:
            if data[ETYPE_INFO2_ETYPE].native is not None:
                tmp.etype = EncryptionTypes(data[ETYPE_INFO2_ETYPE].native)
        if ETYPE_INFO2_SALT in data:
            if data[ETYPE_INFO2_SALT].native is not None:
                tmp.salt = data[ETYPE_INFO2_SALT].native
        return tmp

    def to_asn1(self) -> asn1.EtypeInfoEntryAsn1:
        etype_info = asn1.EtypeInfoEntryAsn1()
        if self._etype is not None:
            etype_info[ETYPE_INFO_ETYPE] = self._etype.value
        if self._salt is not None:
            etype_info[ETYPE_INFO_SALT] = self._salt
        return etype_info


class EtypeInfo:
    _entries: list[EtypeInfoEntry] = None

    def __init__(self):
        self._entries = list()

    def add(self, value):
        self._entries.append(value)

    @classmethod
    def load(cls, data: asn1.EtypeInfoAsn1):
        if isinstance(data, bytes):
            data = asn1.EtypeInfoAsn1.load(data)
        if isinstance(data, EtypeInfo):
            data = data.to_asn1()
        tmp = cls()
        for v in data:
            tmp.add(EtypeInfoEntry.load(v))
        return tmp

    def to_asn1(self) -> asn1.EtypeInfoAsn1:
        tmp = list()
        for v in self._entries:
            tmp.append(v.to_asn1())
        return asn1.EtypeInfoAsn1(tmp)


class EtypeInfo2Entry:
    _etype: EncryptionTypes = None
    _salt: KerberosString = None
    _s2kparams: str = None

    def __init__(self):
        pass

    @property
    def etype(self) -> EncryptionTypes:
        return self._etype

    @etype.setter
    def etype(self, value) -> None:
        self._etype = value

    @property
    def salt(self) -> KerberosString:
        return self._salt

    @salt.setter
    def salt(self, value) -> None:
        self._salt = value

    @property
    def s2kparams(self) -> str:
        return self._s2kparams

    @s2kparams.setter
    def s2kparams(self, value) -> None:
        self._s2kparams = value

    @classmethod
    def load(cls, data: asn1.EtypeInfo2EntryAsn1):
        if isinstance(data, bytes):
            data = asn1.EtypeInfo2EntryAsn1.load(data)
        if isinstance(data, EtypeInfo2Entry):
            data = data.to_asn1()
        tmp = cls()
        if ETYPE_INFO2_ETYPE in data:
            if data[ETYPE_INFO2_ETYPE].native is not None:
                tmp.etype = EncryptionTypes(data[ETYPE_INFO2_ETYPE].native)
        if ETYPE_INFO2_SALT in data:
            if data[ETYPE_INFO2_SALT].native is not None:
                tmp.salt = KerberosString.load(data[ETYPE_INFO2_SALT])
        if ETYPE_INFO2_S2KPARAMS in data:
            if data[ETYPE_INFO2_S2KPARAMS] is not None:
                tmp.s2kparams = data[ETYPE_INFO2_S2KPARAMS].native
        return tmp

    def to_asn1(self) -> asn1.EtypeInfo2EntryAsn1:
        etype_info2_entry = asn1.EtypeInfo2EntryAsn1()
        if self._etype is not None:
            etype_info2_entry[ETYPE_INFO2_ETYPE] = self._etype.value
        if self._salt is not None:
            etype_info2_entry[ETYPE_INFO2_SALT] = self._salt.to_asn1()
        if self._s2kparams is not None:
            etype_info2_entry[ETYPE_INFO2_S2KPARAMS] = self._s2kparams
        return etype_info2_entry


class EtypeInfo2:
    _entries: list[EtypeInfo2Entry] = None

    def __init__(self):
        self._entries = list()

    def add(self, value):
        self._entries.append(value)

    @classmethod
    def load(cls, data: asn1.EtypeInfo2Asn1):
        if isinstance(data, bytes):
            data = asn1.EtypeInfo2Asn1.load(data)
        if isinstance(data, EtypeInfo2):
            data = data.to_asn1()
        tmp = cls()
        for v in data:
            tmp.add(EtypeInfo2Entry.load(v))
        return tmp

    def to_asn1(self) -> asn1.EtypeInfo2Asn1:
        tmp = list()
        for v in self._entries:
            tmp.append(v.to_asn1())
        return asn1.EtypeInfo2Asn1(tmp)


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

    @property
    def padatas(self) -> list:
        return self._padatas

    @classmethod
    def load(cls, data: asn1.PaDatasAsn1):
        if isinstance(data, bytes):
            data = asn1.PaDatasAsn1.load(data)
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


class KrbError:
    _pvno: Int32 = None
    _msg_type: Int32 = None
    _ctime: KerberosTime = None
    _cusec: Int32 = None
    _stime: KerberosTime = None
    _susec: Int32 = None
    _error_code: ErrorCodes = None
    _crealm: Realm = None
    _cname: PrincipalName = None
    _realm: Realm = None
    _sname: PrincipalName = None
    _e_text: str = None
    _e_data: str = None

    def __init__(self):
        pass

    @property
    def pvno(self) -> Int32:
        return self._pvno

    @pvno.setter
    def pvno(self, value) -> None:
        self._pvno = value

    @property
    def msg_type(self) -> Int32:
        return self._msg_type

    @msg_type.setter
    def msg_type(self, value) -> None:
        self._msg_type = value

    @property
    def ctime(self) -> KerberosTime:
        return self._ctime

    @ctime.setter
    def ctime(self, value) -> None:
        self._ctime = value

    @property
    def cusec(self) -> Int32:
        return self._cusec

    @cusec.setter
    def cusec(self, value) -> None:
        self._cusec = value

    @property
    def stime(self) -> KerberosTime:
        return self._stime

    @stime.setter
    def stime(self, value) -> None:
        self._stime = value

    @property
    def susec(self) -> Int32:
        return self._susec

    @susec.setter
    def susec(self, value) -> None:
        self._susec = value

    @property
    def error_code(self) -> ErrorCodes:
        return self._error_code

    @error_code.setter
    def error_code(self, value) -> None:
        self._error_code = value

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
    def realm(self) -> Realm:
        return self._realm

    @realm.setter
    def realm(self, value) -> None:
        self._realm = value

    @property
    def sname(self) -> PrincipalName:
        return self._sname

    @sname.setter
    def sname(self, value) -> None:
        self._sname = value

    @property
    def e_text(self):
        return self._e_text

    @e_text.setter
    def e_text(self, value):
        self._e_text = value

    @property
    def e_data(self):
        return self._e_data

    @e_data.setter
    def e_data(self, value):
        self._e_data = value

    @classmethod
    def load(cls, data: asn1.KrbErrorAsn1):
        if isinstance(data, KrbError):
            data = data.to_asn1()
        tmp = cls()
        if KRB_ERROR_PVNO in data:
            if data[KRB_ERROR_PVNO].native is not None:
                tmp.pvno = Int32.load(data[KRB_ERROR_PVNO])
        if KRB_ERROR_MSG_TYPE in data:
            if data[KRB_ERROR_MSG_TYPE].native is not None:
                tmp.msg_type = Int32.load(data[KRB_ERROR_MSG_TYPE])
        if KRB_ERROR_CTIME in data:
            if data[KRB_ERROR_CTIME].native is not None:
                tmp.ctime = KerberosTime.load(data[KRB_ERROR_CTIME])
        if KRB_ERROR_CUSEC in data:
            if data[KRB_ERROR_CUSEC].native is not None:
                tmp.cusec = Int32.load(data[KRB_ERROR_CUSEC])
        if KRB_ERROR_STIME in data:
            if data[KRB_ERROR_STIME].native is not None:
                tmp.stime = KerberosTime.load(data[KRB_ERROR_STIME])
        if KRB_ERROR_SUSEC in data:
            if data[KRB_ERROR_SUSEC].native is not None:
                tmp.susec = Int32.load(data[KRB_ERROR_SUSEC])
        if KRB_ERROR_ERROR_CODE in data:
            if data[KRB_ERROR_ERROR_CODE].native is not None:
                tmp.error_code = ErrorCodes(data[KRB_ERROR_ERROR_CODE].native)
        if KRB_ERROR_CREALM in data:
            if data[KRB_ERROR_CREALM].native is not None:
                tmp.crealm = Realm.load(data[KRB_ERROR_CREALM])
        if KRB_ERROR_CNAME in data:
            if data[KRB_ERROR_CNAME].native is not None:
                tmp.cname = PrincipalName.load(data[KRB_ERROR_CNAME])
        if KRB_ERROR_REALM in data:
            if data[KRB_ERROR_REALM].native is not None:
                tmp.realm = Realm.load(data[KRB_ERROR_REALM])
        if KRB_ERROR_SNAME in data:
            if data[KRB_ERROR_SNAME].native is not None:
                tmp.sname = PrincipalName.load(data[KRB_ERROR_SNAME])
        if KRB_ERROR_E_TEXT in data:
            if data[KRB_ERROR_E_TEXT].native is not None:
                tmp.e_text = data[KRB_ERROR_E_TEXT].native
        if KRB_ERROR_E_DATA in data:
            if data[KRB_ERROR_E_DATA].native is not None:
                tmp.e_data = data[KRB_ERROR_E_DATA].native
        return tmp

    def to_asn1(self) -> asn1.KrbErrorAsn1:
        krb_err = asn1.KrbErrorAsn1()
        if self._pvno is not None:
            krb_err[KRB_ERROR_PVNO] = self._pvno.to_asn1()
        if self._ctime is not None:
            krb_err[KRB_ERROR_CTIME] = self._ctime.to_asn1()
        if self._cusec is not None:
            krb_err[KRB_ERROR_CUSEC] = self._cusec.to_asn1()
        if self._stime is not None:
            krb_err[KRB_ERROR_STIME] = self._stime.to_asn1()
        if self._susec is not None:
            krb_err[KRB_ERROR_SUSEC] = self._susec.to_asn1()
        if self._error_code is not None:
            krb_err[KRB_ERROR_ERROR_CODE] = self._error_code.value
        if self._crealm is not None:
            krb_err[KRB_ERROR_CREALM] = self._crealm.to_asn1()
        if self._cname is not None:
            krb_err[KRB_ERROR_CNAME] = self._cname.to_asn1()
        if self._realm is not None:
            krb_err[KRB_ERROR_REALM] = self._realm.to_asn1()
        if self._sname is not None:
            krb_err[KRB_ERROR_SNAME] = self._sname.to_asn1()
        if self._e_text is not None:
            krb_err[KRB_ERROR_E_TEXT] = self._e_text
        if self._e_data is not None:
            krb_err[KRB_ERROR_E_DATA] = self._e_data
        return krb_err


class KdcRep:
    _pvno: Int32 = None
    _msg_type: MessageTypes = None
    _pdata: PaDatas = None
    _crealm: Realm = None
    _cname: PrincipalName = None
    _ticket: Ticket = None
    _enc_part: EncryptedData = None

    def __init__(self):
        pass

    @property
    def pvno(self) -> Int32:
        return self._pvno

    @pvno.setter
    def pvno(self, value) -> None:
        self._pvno = value

    @property
    def msg_type(self) -> MessageTypes:
        return self._msg_type

    @msg_type.setter
    def msg_type(self, value) -> None:
        self._msg_type = value

    @property
    def padata(self) -> PaDatas:
        return self._pdata

    @padata.setter
    def padata(self, value) -> None:
        self._pdata = value

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
    def ticket(self) -> Ticket:
        return self._ticket

    @ticket.setter
    def ticket(self, value) -> None:
        self._ticket = value

    @property
    def enc_part(self) -> EncryptedData:
        return self._enc_part

    @enc_part.setter
    def enc_part(self, value) -> None:
        self._enc_part = value

    @classmethod
    def load(cls, data):
        if isinstance(data, KdcRep):
            data = data.to_asn1()
        tmp = cls()
        if KDC_REP_PVNO in data:
            if data[KDC_REP_PVNO].native is not None:
                tmp.pvno = Int32.load(data[KDC_REP_PVNO])
        if KDC_REP_MSG_TYPE in data:
            if data[KDC_REP_MSG_TYPE].native is not None:
                tmp.msg_type = MessageTypes(data[KDC_REP_MSG_TYPE].native)
        if KDC_REP_PADATA in data:
            if data[KDC_REP_PADATA].native is not None:
                tmp.padata = PaDatas.load(data[KDC_REP_PADATA])
        if KDC_REP_CREALM in data:
            if data[KDC_REP_CREALM].native is not None:
                tmp.crealm = Realm.load(data[KDC_REP_CREALM])
        if KDC_REP_CNAME in data:
            if data[KDC_REP_CNAME].native is not None:
                tmp.cname = PrincipalName.load(data[KDC_REP_CNAME])
        if KDC_REP_TICKET in data:
            if data[KDC_REP_TICKET].native is not None:
                tmp.ticket = Ticket.load(data[KDC_REP_TICKET])
        if KDC_REP_ENC_PART in data:
            if data[KDC_REP_ENC_PART].native is not None:
                tmp.enc_part = EncryptedData.load(data[KDC_REP_ENC_PART])
        return tmp

    def to_asn1(self) -> asn1.KdcRepAsn1:
        return asn1.KdcRepAsn1()


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


class EncryptionKey:
    _keytype: EncryptionTypes = None
    _keyvalue: str = None

    def __init__(self):
        pass

    @property
    def keytype(self) -> EncryptionTypes:
        return self._keytype

    @keytype.setter
    def keytype(self, value) -> None:
        self._keytype = value

    @property
    def keyvalue(self) -> str:
        return self._keyvalue

    @keyvalue.setter
    def keyvalue(self, value) -> None:
        self._keyvalue = value

    @classmethod
    def load(cls, data: asn1.EncryptionKeyAsn1):
        if isinstance(data, EncryptionKey):
            data = data.to_asn1()
        tmp = cls()
        if ENCRYPTION_KEY_KEYTYPE in data:
            if data[ENCRYPTION_KEY_KEYTYPE].native is not None:
                tmp.keytype = EncryptionTypes(data[ENCRYPTION_KEY_KEYTYPE].native)
        if ENCRYPTION_KEY_KEYVALUE in data:
            if data[ENCRYPTION_KEY_KEYVALUE].native is not None:
                tmp.keyvalue = data[ENCRYPTION_KEY_KEYVALUE].native
        return tmp

    def to_asn1(self) -> asn1.EncryptionKeyAsn1:
        enc_key = asn1.EncryptionKeyAsn1()
        if self._keytype is not None:
            enc_key[ENCRYPTION_KEY_KEYTYPE] = self._keytype.value
        if self._keyvalue is not None:
            enc_key[ENCRYPTION_KEY_KEYVALUE] = self._keyvalue
        return enc_key


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
