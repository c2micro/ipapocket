from ipapocket.krb5.types.encryption_key import EncryptionKey
from ipapocket.krb5.types.uint32 import UInt32
from ipapocket.krb5.types.last_reqs import LastReqs
from ipapocket.krb5.types.kerberos_time import KerberosTime
from ipapocket.krb5.types.ticket_flags import TicketFlags
from ipapocket.krb5.types.realm import Realm
from ipapocket.krb5.types.principal_name import PrincipalName
from ipapocket.krb5.types.host_addresses import HostAddresses
from ipapocket.krb5.asn1 import EncKdcRepPartAsn1
from ipapocket.krb5.fields import (
    ENC_KDC_REP_PART_AUTHTIME,
    ENC_KDC_REP_PART_CADDR,
    ENC_KDC_REP_PART_ENDTIME,
    ENC_KDC_REP_PART_FLAGS,
    ENC_KDC_REP_PART_KEY,
    ENC_KDC_REP_PART_KEY_EXPIRATION,
    ENC_KDC_REP_PART_LAST_REQ,
    ENC_KDC_REP_PART_NONCE,
    ENC_KDC_REP_PART_RENEW_TILL,
    ENC_KDC_REP_PART_SNAME,
    ENC_KDC_REP_PART_SREALM,
    ENC_KDC_REP_PART_STARTTIME,
)


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
    def load(cls, data: EncKdcRepPartAsn1):
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

    def to_asn1(self) -> EncKdcRepPartAsn1:
        return EncKdcRepPartAsn1()

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()
