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

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()


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

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()


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

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()


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

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()


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

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()


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

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()


class MethodData:
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
    def load(cls, data: asn1.MethodDataAsn1):
        if isinstance(data, bytes):
            data = asn1.MethodDataAsn1.load(data)
        if isinstance(data, MethodData):
            data = data.to_asn1()
        tmp = cls()
        for v in data.native:
            tmp.add(PaData.load(v))
        return tmp

    def to_asn1(self):
        tmp = list()
        for pa_data in self._padatas:
            tmp.append(pa_data.to_asn1())
        return asn1.MethodDataAsn1(tuple(tmp))

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()


class KdcReq:
    _pvno: Int32 = None
    _msg_type: MessageTypes = None
    _padata: MethodData = None
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
    def padata(self) -> MethodData:
        return self._padata

    @padata.setter
    def padata(self, value) -> None:
        if not isinstance(value, MethodData):
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
                tmp.padata = MethodData.load(data[KDC_REQ_PADATA])
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

    def pretty(self):
        """
        Convert object to dict
        """
        tmp = dict()
        if self.pvno is not None:
            tmp[KDC_REQ_PVNO] = self.pvno.pretty()
        else:
            tmp[KDC_REQ_PVNO] = None
        if self.msg_type is not None:
            tmp[KDC_REQ_MSG_TYPE] = self.msg_type.name
        else:
            tmp[KDC_REQ_MSG_TYPE] = None
        if self.req_body is not None:
            tmp[KDC_REQ_REQ_BODY] = self.req_body.pretty()
        else:
            tmp[KDC_REQ_REQ_BODY] = None
        if self.padata is not None:
            tmp[KDC_REQ_PADATA] = self.padata.pretty()
        else:
            tmp[KDC_REQ_PADATA] = None
        return {KDC_REQ: tmp}

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()


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

    def pretty(self):
        """
        Convert object to dict
        """
        if self.req is not None:
            value = self.req.pretty()
        else:
            value = None
        return {AS_REQ: value}

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()


class TgsReq:
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
            raise InvalidTgsReqRequest()

    @classmethod
    def load(cls, data: asn1.TgsReqAsn1):
        if isinstance(data, TgsReq):
            data = data.to_asn1()
        return cls(KdcReq.load(data))

    def to_asn1(self):
        return asn1.TgsReqAsn1(self._req.to_asn1().native)

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()


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

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()


class KdcRep:
    _pvno: Int32 = None
    _msg_type: MessageTypes = None
    _pdata: MethodData = None
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
    def padata(self) -> MethodData:
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
                tmp.padata = MethodData.load(data[KDC_REP_PADATA])
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

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()


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
