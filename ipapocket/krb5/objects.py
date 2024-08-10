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
        return cls(data.native)

    def __str__(self) -> str:
        return "{}".format(self._value)

    def _validate_value(self, value) -> int:
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
        return cls(data.native)

    def __str__(self) -> str:
        return "{}".format(self._value)

    def _validate_value(self, value) -> int:
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
        return cls(data.native)

    def __str__(self) -> str:
        return "{}".format(self._value)

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
        return cls(data.native)

    def __str__(self) -> str:
        return "{}".format(self._value)

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
        return cls(data.native)

    def __str__(self) -> str:
        tmp = "["
        for i in range(len(self._value)):
            if i == len(self._value) - 1:
                tmp += "'{}']".format(self._value[i])
            else:
                tmp += "'{}', ".format(self._value[i])
        return tmp

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
        return cls(
            type=PrincipalType(data.native[PRINCIPAL_NAME_NAME_TYPE]),
            value=data.native[PRINCIPAL_NAME_NAME_STRING],
        )

    def __str__(self):
        return "{{'{}' = {}, '{}' = {}}}".format(
            PRINCIPAL_NAME_NAME_TYPE,
            self._type.name,
            PRINCIPAL_NAME_NAME_STRING,
            self._value,
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
        return cls(realm=data.native)

    def __str__(self) -> str:
        return "{}".format(self._realm)

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

    def __str__(self) -> str:
        options = self._options.flags
        tmp = "["
        for i in range(len(options)):
            if i == len(options) - 1:
                tmp += "'{}']".format(options[i].name)
            else:
                tmp += "'{}', ".format(options[i].name)
        return tmp

    @classmethod
    def load(cls, value: asn1.KdcOptionsAsn1):
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

    def __str__(self) -> str:
        flags = self._flags.flags
        tmp = "["
        for i in range(len(flags)):
            if i == len(flags) - 1:
                tmp += "'{}']".format(flags[i].name)
            else:
                tmp += "'{}', ".format(flags[i].name)
        return tmp

    @classmethod
    def load(cls, value: asn1.TicketFlagsAsn1):
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

    def __str__(self) -> str:
        return "{}".format(self._time)

    @classmethod
    def load(cls, data: asn1.KerberosTimeAsn1):
        return cls(data.native)

    def to_asn1(self):
        return asn1.KerberosTimeAsn1(self._time)


class EncTypes:
    def __init__(self, etypes=None):
        self._etypes = etypes

    def to_asn1(self):
        final = list()
        for t in self._etypes:
            final.append(t.value)
        return asn1.EncTypesAsn1(final)


class KdcReqBody:
    def __init__(self):
        self._kdc_options = None
        self._cname = None
        self._realm = None
        self._sname = None
        self._till = None
        self._rtime = None
        self._nonce = None
        self._etype = None

    def set_kdc_options(self, options):
        self._kdc_options = options

    def set_cname(self, cname):
        self._cname = cname

    def set_realm(self, realm):
        self._realm = realm

    def set_sname(self, sname):
        self._sname = sname

    def set_till(self, till):
        self._till = till

    def set_rtime(self, rtime):
        self._rtime = rtime

    def set_nonce(self, nonce):
        self._nonce = nonce

    def set_etypes(self, etypes):
        self._etype = etypes

    def to_asn1(self):
        kdc_req_body = asn1.KdcReqBodyAsn1()
        if self._kdc_options is not None:
            kdc_req_body["kdc-options"] = self._kdc_options.to_asn1()
        if self._cname is not None:
            kdc_req_body["cname"] = self._cname.to_asn1()
        if self._realm is not None:
            kdc_req_body["realm"] = self._realm.to_asn1()
        if self._sname is not None:
            kdc_req_body["sname"] = self._sname.to_asn1()
        if self._till is not None:
            kdc_req_body["till"] = self._till.to_asn1()
        if self._rtime is not None:
            kdc_req_body["rtime"] = self._rtime.to_asn1()
        if self._nonce is not None:
            kdc_req_body["nonce"] = self._nonce.to_asn1()
        if self._etype is not None:
            kdc_req_body["etype"] = self._etype.to_asn1()
        return kdc_req_body


class PaEncTsEnc:
    def __init__(self, krb_time: KerberosTime, micros: Microseconds):
        self._timestamp = krb_time
        self._micros = micros

    def to_asn1(self):
        pa_enc_ts_enc = asn1.PaEncTsEncAsn1()
        if self._timestamp is not None:
            pa_enc_ts_enc["patimestamp"] = self._timestamp.to_asn1()
        if self._micros is not None:
            pa_enc_ts_enc["pausec"] = self._micros.to_asn1()
        return pa_enc_ts_enc


class EncryptedData:
    def __init__(self, etype: Int32, kvno: UInt32, cipher):
        self._etype = etype
        self._kvno = kvno
        self._cipher = cipher

    def to_asn1(self):
        enc_data = asn1.EncryptedDataAsn1()
        if self._etype is not None:
            enc_data["etype"] = self._etype.to_asn1()
        if self._kvno is not None:
            enc_data["kvno"] = self._kvno.to_asn1()
        if self._cipher is not None:
            enc_data["cipher"] = self._cipher
        return enc_data


class PaData:
    def __init__(self, type=None, value=None):
        self._type = type
        self._value = value

    def to_asn1(self):
        pa_data = asn1.PaDataAsn1()
        if self._type is not None:
            pa_data["padata-type"] = self._type.to_asn1()
        if self._value is not None:
            pa_data["padata-value"] = self._value.to_asn1().dump()
        return pa_data


class PaDatas:
    def __init__(self):
        self._pa_datas = list()

    def add_padata(self, padata: PaData):
        self._pa_datas.append(padata)

    def to_asn1(self):
        tmp = list()
        for pa_data in self._pa_datas:
            tmp.append(pa_data.to_asn1())
        return asn1.PaDatasAsn1(tuple(tmp))


class KdcReq:
    def __init__(self):
        self._pvno = None
        self._msg_type = None
        self._padatas = None
        self._req_body = None

    def set_pvno(self, pvno):
        self._pvno = pvno

    def set_msg_type(self, msg_type):
        self._msg_type = msg_type

    def set_req_body(self, req_body):
        self._req_body = req_body

    def set_padatas(self, padatas: PaDatas):
        self._padatas = padatas

    def to_asn1(self):
        kdc_req = asn1.KdcReqAsn1()
        if self._pvno is not None:
            kdc_req["pvno"] = self._pvno.to_asn1()
        if self._msg_type is not None:
            kdc_req["msg-type"] = self._msg_type.to_asn1()
        if self._req_body is not None:
            kdc_req["req-body"] = self._req_body.to_asn1()
        if self._padatas is not None:
            kdc_req["padata"] = self._padatas.to_asn1()
        return kdc_req


class AsReq:
    def __init__(self, req):
        self._req = req

    def set_req(self, req):
        self._req = req

    def to_asn1(self):
        return asn1.AsReqAsn1(self._req.to_asn1().native)
