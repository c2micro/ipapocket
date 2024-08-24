from ipapocket.krb5.types.krb_cred_infos import KrbCredInfos
from ipapocket.krb5.types.uint32 import UInt32
from ipapocket.krb5.types.microseconds import Microseconds
from ipapocket.krb5.types.host_address import HostAddress
from ipapocket.krb5.types.kerberos_time import KerberosTime
from ipapocket.krb5.asn1 import EncKrbCredPartAsn1
from ipapocket.krb5.constants.fields import (
    ENC_KRB_CRED_PART_NONCE,
    ENC_KRB_CRED_PART_R_ADDRESS,
    ENC_KRB_CRED_PART_S_ADDRESS,
    ENC_KRB_CRED_PART_TICKET_INFO,
    ENC_KRB_CRED_PART_TIMESTAMP,
    ENC_KRB_CRED_PART_USEC,
)


class EncKrbCredPart:
    _ticket_info: KrbCredInfos = None
    _nonce: UInt32 = None
    _timestamp: KerberosTime = None
    _usec: Microseconds = None
    _s_address: HostAddress = None
    _r_address: HostAddress = None

    @property
    def ticket_info(self) -> KrbCredInfos:
        return self._ticket_info

    @ticket_info.setter
    def ticket_info(self, value) -> None:
        self._ticket_info = value

    @property
    def nonce(self) -> UInt32:
        return self._nonce

    @nonce.setter
    def nonce(self, value) -> None:
        self._nonce = value

    @property
    def timestamp(self) -> KerberosTime:
        return self._timestamp

    @timestamp.setter
    def timestamp(self, value) -> None:
        self._timestamp = value

    @property
    def usec(self) -> Microseconds:
        return self._usec

    @usec.setter
    def usec(self, value) -> None:
        self._usec = value

    @property
    def s_address(self) -> HostAddress:
        return self._s_address

    @s_address.setter
    def s_address(self, value) -> None:
        self._s_address = value

    @property
    def r_address(self) -> HostAddress:
        return self._r_address

    @r_address.setter
    def r_address(self, value) -> None:
        self._r_address = value

    @classmethod
    def load(cls, data: EncKrbCredPartAsn1):
        if isinstance(data, EncKrbCredPart):
            data = data.to_asn1()
        tmp = cls()
        if ENC_KRB_CRED_PART_TICKET_INFO in data:
            if data[ENC_KRB_CRED_PART_TICKET_INFO].native is not None:
                tmp.ticket_info = KrbCredInfos.load(data[ENC_KRB_CRED_PART_TICKET_INFO])
        if ENC_KRB_CRED_PART_NONCE in data:
            if data[ENC_KRB_CRED_PART_NONCE].native is not None:
                tmp.nonce = UInt32.load(data[ENC_KRB_CRED_PART_NONCE])
        if ENC_KRB_CRED_PART_TIMESTAMP in data:
            if data[ENC_KRB_CRED_PART_TIMESTAMP].native is not None:
                tmp.timestamp = KerberosTime.load(data[ENC_KRB_CRED_PART_TIMESTAMP])
        if ENC_KRB_CRED_PART_USEC in data:
            if data[ENC_KRB_CRED_PART_USEC].native is not None:
                tmp.usec = Microseconds.load(data[ENC_KRB_CRED_PART_USEC])
        if ENC_KRB_CRED_PART_S_ADDRESS in data:
            if data[ENC_KRB_CRED_PART_S_ADDRESS].native is not None:
                tmp.s_address = HostAddress.load(data[ENC_KRB_CRED_PART_S_ADDRESS])
        if ENC_KRB_CRED_PART_R_ADDRESS in data:
            if data[ENC_KRB_CRED_PART_R_ADDRESS].native is not None:
                tmp.r_address = HostAddress.load(data[ENC_KRB_CRED_PART_R_ADDRESS])
        return tmp

    def to_asn1(self) -> EncKrbCredPartAsn1:
        tmp = EncKrbCredPartAsn1()
        if self.ticket_info is not None:
            tmp[ENC_KRB_CRED_PART_TICKET_INFO] = self.ticket_info.to_asn1()
        if self.nonce is not None:
            tmp[ENC_KRB_CRED_PART_NONCE] = self.nonce.to_asn1()
        if self.timestamp is not None:
            tmp[ENC_KRB_CRED_PART_TIMESTAMP] = self.timestamp.to_asn1()
        if self.usec is not None:
            tmp[ENC_KRB_CRED_PART_USEC] = self.usec.to_asn1()
        if self.s_address is not None:
            tmp[ENC_KRB_CRED_PART_S_ADDRESS] = self.s_address.to_asn1()
        if self.r_address is not None:
            tmp[ENC_KRB_CRED_PART_R_ADDRESS] = self.r_address.to_asn1()
        return tmp

    def dump(self) -> bytes:
        return self.to_asn1().dump()