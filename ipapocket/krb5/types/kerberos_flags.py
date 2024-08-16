import enum
from bitarray import bitarray
from ipapocket.exceptions.krb5 import InvalidKerberosFlagsValueType
from ipapocket.krb5.asn1 import KerberosFlagsAsn1


class KerberosFlags:
    _flags: list = None

    def __init__(self):
        self._flags = list()

    @property
    def flags(self) -> list:
        return self._flags

    def add(self, flag):
        self._flags.append(self._validate_flag(flag))

    def clear(self):
        self._flags = list()

    def _validate_flag(self, flag):
        if not isinstance(flag, enum.Enum):
            raise InvalidKerberosFlagsValueType(flag)
        return flag

    def to_asn1(self) -> KerberosFlagsAsn1:
        """
        Convert object to ASN1
        """
        b_arr = bitarray(32)
        for flag in self._flags:
            b_arr[flag.value] = 1
        return KerberosFlagsAsn1(tuple(b_arr.tolist()))

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()
