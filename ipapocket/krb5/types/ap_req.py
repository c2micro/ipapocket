from ipapocket.krb5.types.int32 import Int32
from ipapocket.krb5.types.ap_options import ApOptions
from ipapocket.krb5.types.ticket import Ticket
from ipapocket.krb5.types.encrypted_data import EncryptedData
from ipapocket.krb5.constants import MessageTypes
from ipapocket.krb5.fields import (
    AP_REQ_AP_OPTIONS,
    AP_REQ_AUTHENTICATOR,
    AP_REQ_MSG_TYPE,
    AP_REQ_PVNO,
    AP_REQ_TICKET,
)
from ipapocket.krb5.asn1 import ApReqAsn1


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
    def load(cls, data: ApReqAsn1):
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

    def to_asn1(self) -> ApReqAsn1:
        ap_req = ApReqAsn1()
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
