from ipapocket.krb5.types.host_address import HostAddress
from ipapocket.krb5.asn1 import HostAddressesAsn1


class HostAddresses:
    _addresses: list[HostAddress] = None

    def __init__(self):
        self._addresses = list()

    def add(self, value):
        self._addresses.append(value)

    def clear(self):
        self._addresses = list()

    @classmethod
    def load(cls, data: HostAddressesAsn1):
        if isinstance(data, HostAddresses):
            data = data.to_asn1()
        tmp = cls()
        for v in data:
            tmp.add(HostAddress.load(v))
        return tmp

    def to_asn1(self) -> HostAddressesAsn1:
        tmp = list()
        for v in self._addresses:
            tmp.append(v.to_asn1())
        return HostAddressesAsn1(tmp)

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()
