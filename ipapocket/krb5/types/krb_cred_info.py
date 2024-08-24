from ipapocket.krb5.types.encryption_key import EncryptionKey
from ipapocket.krb5.types.realm import Realm
from ipapocket.krb5.types.principal_name import PrincipalName
from ipapocket.krb5.types.ticket_flags import TicketFlags
from ipapocket.krb5.types.kerberos_time import KerberosTime
from ipapocket.krb5.types.host_addresses import HostAddresses
from ipapocket.krb5.asn1 import KrbCredInfoAsn1
from ipapocket.krb5.constants.fields import (
    KRB_CRED_INFO_AUTHTIME,
    KRB_CRED_INFO_FLAGS,
    KRB_CRED_INFO_CADDR,
    KRB_CRED_INFO_ENDTIME,
    KRB_CRED_INFO_STARTTIME,
    KRB_CRED_INFO_KEY,
    KRB_CRED_INFO_PNAME,
    KRB_CRED_INFO_PREALM,
    KRB_CRED_INFO_RENEW_TILL,
    KRB_CRED_INFO_SNAME,
    KRB_CRED_INFO_SREALM,
)


class KrbCredInfo:
    _key: EncryptionKey = None
    _prealm: Realm = None
    _pname: PrincipalName = None
    _flags: TicketFlags = None
    _authtime: KerberosTime = None
    _starttime: KerberosTime = None
    _endtime: KerberosTime = None
    _renew_till: KerberosTime = None
    _srealm: Realm = None
    _sname: PrincipalName = None
    _caddr: HostAddresses = None

    @property
    def key(self) -> EncryptionKey:
        return self._key

    @key.setter
    def key(self, value) -> None:
        self._key = value

    @property
    def prealm(self) -> Realm:
        return self._prealm

    @prealm.setter
    def prealm(self, value) -> None:
        self._prealm = value

    @property
    def pname(self) -> PrincipalName:
        return self._pname

    @pname.setter
    def pname(self, value) -> None:
        self._pname = value

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
    def load(cls, data: KrbCredInfoAsn1):
        if isinstance(data, KrbCredInfo):
            data = data.to_asn1()
        tmp = cls()
        if KRB_CRED_INFO_KEY in data:
            if data[KRB_CRED_INFO_KEY].native is not None:
                tmp.key = EncryptionKey.load(data[KRB_CRED_INFO_KEY])
        if KRB_CRED_INFO_PREALM in data:
            if data[KRB_CRED_INFO_PREALM].native is not None:
                tmp.prealm = Realm.load(data[KRB_CRED_INFO_PREALM])
        if KRB_CRED_INFO_PNAME in data:
            if data[KRB_CRED_INFO_PNAME].native is not None:
                tmp.pname = PrincipalName.load(data[KRB_CRED_INFO_PNAME])
        if KRB_CRED_INFO_FLAGS in data:
            if data[KRB_CRED_INFO_FLAGS].native is not None:
                tmp.flags = TicketFlags.load(data[KRB_CRED_INFO_FLAGS])
        if KRB_CRED_INFO_AUTHTIME in data:
            if data[KRB_CRED_INFO_AUTHTIME].native is not None:
                tmp.authtime = KerberosTime.load(data[KRB_CRED_INFO_AUTHTIME])
        if KRB_CRED_INFO_STARTTIME in data:
            if data[KRB_CRED_INFO_STARTTIME].native is not None:
                tmp.starttime = KerberosTime.load(data[KRB_CRED_INFO_STARTTIME])
        if KRB_CRED_INFO_ENDTIME in data:
            if data[KRB_CRED_INFO_ENDTIME].native is not None:
                tmp.endtime = KerberosTime.load(data[KRB_CRED_INFO_ENDTIME])
        if KRB_CRED_INFO_RENEW_TILL in data:
            if data[KRB_CRED_INFO_RENEW_TILL].native is not None:
                tmp.renew_till = KerberosTime.load(data[KRB_CRED_INFO_RENEW_TILL])
        if KRB_CRED_INFO_SNAME in data:
            if data[KRB_CRED_INFO_SNAME].native is not None:
                tmp.sname = PrincipalName.load(data[KRB_CRED_INFO_SNAME])
        if KRB_CRED_INFO_SREALM in data:
            if data[KRB_CRED_INFO_SREALM].native is not None:
                tmp.srealm = Realm.load(data[KRB_CRED_INFO_SREALM])
        if KRB_CRED_INFO_CADDR in data:
            if data[KRB_CRED_INFO_CADDR].native is not None:
                tmp.caddr = HostAddresses.load(data[KRB_CRED_INFO_CADDR])
        return tmp

    def to_asn1(self) -> KrbCredInfoAsn1:
        tmp = KrbCredInfoAsn1()
        if self.key is not None:
            tmp[KRB_CRED_INFO_KEY] = self.key.to_asn1()
        if self.prealm is not None:
            tmp[KRB_CRED_INFO_PREALM] = self.prealm.to_asn1()
        if self.pname is not None:
            tmp[KRB_CRED_INFO_PNAME] = self.pname.to_asn1()
        if self.flags is not None:
            tmp[KRB_CRED_INFO_FLAGS] = self.flags.to_asn1()
        if self.authtime is not None:
            tmp[KRB_CRED_INFO_AUTHTIME] = self.authtime.to_asn1()
        if self.starttime is not None:
            tmp[KRB_CRED_INFO_STARTTIME] = self.starttime.to_asn1()
        if self.endtime is not None:
            tmp[KRB_CRED_INFO_ENDTIME] = self.endtime.to_asn1()
        if self.renew_till is not None:
            tmp[KRB_CRED_INFO_RENEW_TILL] = self.renew_till.to_asn1()
        if self.srealm is not None:
            tmp[KRB_CRED_INFO_SREALM] = self.srealm.to_asn1()
        if self.sname is not None:
            tmp[KRB_CRED_INFO_SNAME] = self.sname.to_asn1()
        if self.caddr is not None:
            tmp[KRB_CRED_INFO_CADDR] = self.caddr.to_asn1()
        return tmp
