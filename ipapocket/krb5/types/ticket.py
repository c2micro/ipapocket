from ipapocket.krb5.types.int32 import Int32
from ipapocket.krb5.types.realm import Realm
from ipapocket.krb5.types.principal_name import PrincipalName
from ipapocket.krb5.types.encrypted_data import EncryptedData
from ipapocket.krb5.asn1 import TicketAsn1
from ipapocket.krb5.constants.fields import (
    TICKET_TKT_VNO,
    TICKET_SNAME,
    TICKET_ENC_PART,
    TICKET_REALM,
)


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
    def load(cls, data: TicketAsn1):
        if isinstance(data, bytes):
            data = TicketAsn1.load(data)
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

    def to_asn1(self) -> TicketAsn1:
        ticket = TicketAsn1()
        if self._tkt_vno is not None:
            ticket[TICKET_TKT_VNO] = self._tkt_vno.to_asn1()
        if self._realm is not None:
            ticket[TICKET_REALM] = self._realm.to_asn1()
        if self._sname is not None:
            ticket[TICKET_SNAME] = self._sname.to_asn1()
        if self._enc_part is not None:
            ticket[TICKET_ENC_PART] = self._enc_part.to_asn1()
        return ticket

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()
