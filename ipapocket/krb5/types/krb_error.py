from ipapocket.krb5.types.int32 import Int32
from ipapocket.krb5.types.kerberos_time import KerberosTime
from ipapocket.krb5.types.realm import Realm
from ipapocket.krb5.types.principal_name import PrincipalName
from ipapocket.krb5.constants import ErrorCodes
from ipapocket.krb5.fields import (
    KRB_ERROR_CNAME,
    KRB_ERROR_CREALM,
    KRB_ERROR_CTIME,
    KRB_ERROR_CUSEC,
    KRB_ERROR_E_DATA,
    KRB_ERROR_E_TEXT,
    KRB_ERROR_ERROR_CODE,
    KRB_ERROR_MSG_TYPE,
    KRB_ERROR_PVNO,
    KRB_ERROR_REALM,
    KRB_ERROR_SNAME,
    KRB_ERROR_STIME,
    KRB_ERROR_SUSEC,
)
from ipapocket.krb5.asn1 import KrbErrorAsn1


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
    def load(cls, data: KrbErrorAsn1):
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

    def to_asn1(self) -> KrbErrorAsn1:
        krb_err = KrbErrorAsn1()
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
