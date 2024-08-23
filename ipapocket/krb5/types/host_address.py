from ipapocket.krb5.types.int32 import Int32
from ipapocket.krb5.asn1 import HostAddressAsn1
from ipapocket.krb5.constants.fields import HOST_ADDRESS_ADDR_TYPE, HOST_ADDRESS_ADDRESS


class HostAddress:
    _type: Int32 = None
    _address = None

    def __init__(self, type=None, address=None):
        self._type = type
        self._address = address

    @property
    def type(self) -> Int32:
        return self._type

    @type.setter
    def type(self, value) -> None:
        self._type = value

    @property
    def address(self):
        return self._address

    @address.setter
    def address(self, value) -> None:
        self._address = value

    @classmethod
    def load(cls, data: HostAddressAsn1):
        if isinstance(data, HostAddress):
            data = data.to_asn1()
        tmp = cls()
        if HOST_ADDRESS_ADDR_TYPE in data:
            if data[HOST_ADDRESS_ADDR_TYPE].native is not None:
                tmp.type = Int32.load(data[HOST_ADDRESS_ADDR_TYPE])
        if HOST_ADDRESS_ADDRESS in data:
            if data[HOST_ADDRESS_ADDRESS].native is not None:
                tmp.address = data[HOST_ADDRESS_ADDRESS].native
        return tmp

    def to_asn1(self) -> HostAddressAsn1:
        host_address = HostAddressAsn1()
        if self._type is not None:
            host_address[HOST_ADDRESS_ADDR_TYPE] = self._type.to_asn1()
        if self._address is not None:
            host_address[HOST_ADDRESS_ADDRESS] = self._address
        return host_address

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()
