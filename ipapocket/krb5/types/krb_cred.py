from ipapocket.krb5.types.int32 import Int32
from ipapocket.krb5.constants import KRB5_VERSION, MessageType
from ipapocket.krb5.types.tickets import Tickets
from ipapocket.krb5.types.encrypted_data import EncryptedData
from ipapocket.krb5.types.enc_krb_cred_part import EncKrbCredPart
from ipapocket.krb5.asn1 import KrbCredAsn1
from ipapocket.krb5.constants.fields import (
    KRB_CRED_PVNO,
    KRB_CRED_MSG_TYPE,
    KRB_CRED_TICKETS,
    KRB_CRED_ENC_PART,
)


class KrbCred:
    _pvno: Int32 = Int32(KRB5_VERSION)
    _msg_type: MessageType = None
    _tickets: Tickets = None
    _enc_part: EncryptedData = None

    @property
    def pvno(self) -> Int32:
        return self._pvno

    @pvno.setter
    def pvno(self, value) -> None:
        self._pvno = value

    @property
    def msg_type(self) -> MessageType:
        return self._msg_type

    @msg_type.setter
    def msg_type(self, value) -> None:
        self._msg_type = value

    @property
    def tickets(self) -> Tickets:
        return self._tickets

    @tickets.setter
    def tickets(self, value) -> None:
        self._tickets = value

    @property
    def enc_part(self) -> EncryptedData:
        return self._enc_part

    @enc_part.setter
    def enc_part(self, value) -> None:
        self._enc_part = value

    @classmethod
    def load(cls, data: KrbCredAsn1):
        if isinstance(data, KrbCred):
            data = data.to_asn1()
        if isinstance(data, bytes):
            data = KrbCredAsn1.load(data)
        tmp = cls()
        if KRB_CRED_PVNO in data:
            if data[KRB_CRED_PVNO].native is not None:
                tmp.pvno = Int32.load(data[KRB_CRED_PVNO])
        if KRB_CRED_MSG_TYPE in data:
            if data[KRB_CRED_MSG_TYPE].native is not None:
                tmp.msg_type = MessageType(data[KRB_CRED_MSG_TYPE].native)
        if KRB_CRED_TICKETS in data:
            if data[KRB_CRED_TICKETS].native is not None:
                tmp.tickets = Tickets.load(data[KRB_CRED_TICKETS])
        if KRB_CRED_ENC_PART in data:
            if data[KRB_CRED_ENC_PART].native is not None:
                tmp.enc_part = EncryptedData.load(data[KRB_CRED_ENC_PART])
        return tmp

    def to_asn1(self) -> KrbCredAsn1:
        tmp = KrbCredAsn1()
        if self.pvno is not None:
            tmp[KRB_CRED_PVNO] = self.pvno.to_asn1()
        if self.msg_type is not None:
            tmp[KRB_CRED_MSG_TYPE] = self.msg_type.value
        if self.tickets is not None:
            tmp[KRB_CRED_TICKETS] = self.tickets.to_asn1()
        if self.enc_part is not None:
            tmp[KRB_CRED_ENC_PART] = self.enc_part.to_asn1()
        return tmp

    def dump(self) -> bytes:
        return self.to_asn1().dump()