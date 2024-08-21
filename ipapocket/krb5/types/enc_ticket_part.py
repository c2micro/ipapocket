from ipapocket.krb5.types.ticket_flags import TicketFlags
from ipapocket.krb5.types.realm import Realm
from ipapocket.krb5.types.principal_name import PrincipalName
from ipapocket.krb5.types.kerberos_time import KerberosTime
from ipapocket.krb5.types.transited_encoding import TransitedEncoding
from ipapocket.krb5.types.encryption_key import EncryptionKey
from ipapocket.krb5.types.host_addresses import HostAddresses
from ipapocket.krb5.types.authorization_data import AuthorizationData
from ipapocket.krb5.asn1 import EncTicketPartAsn1
from ipapocket.krb5.fields import (
    ENC_TICKET_PART_AUTHORIZATION_DATA,
    ENC_TICKET_PART_AUTHTIME,
    ENC_TICKET_PART_CADDR,
    ENC_TICKET_PART_CNAME,
    ENC_TICKET_PART_CREALM,
    ENC_TICKET_PART_ENDTIME,
    ENC_TICKET_PART_FLAGS,
    ENC_TICKET_PART_KEY,
    ENC_TICKET_PART_RENEW_TILL,
    ENC_TICKET_PART_STARTTIME,
    ENC_TICKET_PART_TRANSITED,
)


class EncTicketPart:
    _flags: TicketFlags = None
    _key: EncryptionKey = None
    _crealm: Realm = None
    _cname: PrincipalName = None
    _transited: TransitedEncoding = None
    _authtime: KerberosTime = None
    _starttime: KerberosTime = None
    _endtime: KerberosTime = None
    _renew_till: KerberosTime = None
    _caddr: HostAddresses = None
    _authorization_data: AuthorizationData = None

    @property
    def flags(self) -> TicketFlags:
        return self._flags

    @flags.setter
    def flags(self, value) -> None:
        self._flags = value

    @property
    def key(self) -> EncryptionKey:
        return self._key

    @key.setter
    def key(self, value) -> None:
        self._key = value

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
    def transited(self) -> TransitedEncoding:
        return self._transited

    @transited.setter
    def transited(self, value) -> None:
        self._transited = value

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
    def caddr(self) -> HostAddresses:
        return self._caddr

    @caddr.setter
    def caddr(self, value) -> None:
        self._caddr = value

    @property
    def authorization_data(self) -> AuthorizationData:
        return self._authorization_data

    @authorization_data.setter
    def authorization_data(self, value) -> None:
        self._authorization_data = value

    @classmethod
    def load(cls, data: EncTicketPartAsn1):
        if isinstance(data, EncTicketPart):
            data = data.to_asn1()
        if isinstance(data, bytes):
            data = EncTicketPartAsn1.load(data)
        tmp = cls()
        if ENC_TICKET_PART_FLAGS in data:
            if data[ENC_TICKET_PART_FLAGS].native is not None:
                tmp.flags = TicketFlags.load(data[ENC_TICKET_PART_FLAGS])
        if ENC_TICKET_PART_KEY in data:
            if data[ENC_TICKET_PART_KEY].native is not None:
                tmp.key = EncryptionKey.load(data[ENC_TICKET_PART_KEY])
        if ENC_TICKET_PART_CREALM in data:
            if data[ENC_TICKET_PART_CREALM].native is not None:
                tmp.crealm = Realm.load(data[ENC_TICKET_PART_CREALM])
        if ENC_TICKET_PART_CNAME in data:
            if data[ENC_TICKET_PART_CNAME].native is not None:
                tmp.cname = PrincipalName.load(data[ENC_TICKET_PART_CNAME])
        if ENC_TICKET_PART_TRANSITED in data:
            if data[ENC_TICKET_PART_TRANSITED].native is not None:
                tmp.transited = TransitedEncoding.load(data[ENC_TICKET_PART_TRANSITED])
        if ENC_TICKET_PART_AUTHTIME in data:
            if data[ENC_TICKET_PART_AUTHTIME].native is not None:
                tmp.authtime = KerberosTime.load(data[ENC_TICKET_PART_AUTHTIME])
        if ENC_TICKET_PART_STARTTIME in data:
            if data[ENC_TICKET_PART_STARTTIME].native is not None:
                tmp.starttime = KerberosTime.load(data[ENC_TICKET_PART_STARTTIME])
        if ENC_TICKET_PART_ENDTIME in data:
            if data[ENC_TICKET_PART_ENDTIME].native is not None:
                tmp.endtime = KerberosTime.load(data[ENC_TICKET_PART_ENDTIME])
        if ENC_TICKET_PART_RENEW_TILL in data:
            if data[ENC_TICKET_PART_RENEW_TILL].native is not None:
                tmp.renew_till = KerberosTime.load(data[ENC_TICKET_PART_RENEW_TILL])
        if ENC_TICKET_PART_CADDR in data:
            if data[ENC_TICKET_PART_CADDR].native is not None:
                tmp.caddr = HostAddresses.load(data[ENC_TICKET_PART_CADDR])
        if ENC_TICKET_PART_AUTHORIZATION_DATA in data:
            if data[ENC_TICKET_PART_AUTHORIZATION_DATA].native is not None:
                tmp.authorization_data = AuthorizationData.load(
                    data[ENC_TICKET_PART_AUTHORIZATION_DATA]
                )
        return tmp

    def to_asn1(self) -> EncTicketPartAsn1:
        enc_ticket_part = EncTicketPartAsn1()
        if self.flags is not None:
            enc_ticket_part[ENC_TICKET_PART_FLAGS] = self.flags.to_asn1()
        if self.key is not None:
            enc_ticket_part[ENC_TICKET_PART_KEY] = self.key.to_asn1()
        if self.crealm is not None:
            enc_ticket_part[ENC_TICKET_PART_CREALM] = self.crealm.to_asn1()
        if self.cname is not None:
            enc_ticket_part[ENC_TICKET_PART_CNAME] = self.cname.to_asn1()
        if self.transited is not None:
            enc_ticket_part[ENC_TICKET_PART_TRANSITED] = self.transited.to_asn1()
        if self.authtime is not None:
            enc_ticket_part[ENC_TICKET_PART_AUTHTIME] = self.authtime.to_asn1()
        if self.starttime is not None:
            enc_ticket_part[ENC_TICKET_PART_STARTTIME] = self.starttime.to_asn1()
        if self.endtime is not None:
            enc_ticket_part[ENC_TICKET_PART_ENDTIME] = self.endtime.to_asn1()
        if self.renew_till is not None:
            enc_ticket_part[ENC_TICKET_PART_RENEW_TILL] = self.renew_till.to_asn1()
        if self.caddr is not None:
            enc_ticket_part[ENC_TICKET_PART_CADDR] = self.caddr.to_asn1()
        if self.authorization_data is not None:
            enc_ticket_part[ENC_TICKET_PART_AUTHORIZATION_DATA] = (
                self.authorization_data.to_asn1()
            )
        return enc_ticket_part
