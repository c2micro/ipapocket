from ipapocket.krb5.asn1 import UInt32Asn1
from ipapocket.krb5.constants import MIN_UINT32, MAX_UINT32
from ipapocket.exceptions.krb5 import InvalidUInt32Value
import enum


class UInt32:
    _value: int = 0

    def __init__(self, value=None):
        self.value = value

    @classmethod
    def load(cls, data: UInt32Asn1):
        """
        Create object of UInt32 from ASN1 structure
        """
        if isinstance(data, UInt32):
            data = data.to_asn1()
        if isinstance(data, int):
            return cls(data)
        return cls(data.native)

    def _validate_value(self, value) -> int:
        if value is None:
            return 0
        if isinstance(value, UInt32):
            return value.value
        if isinstance(value, enum.Enum):
            value = value.value
        if not isinstance(value, int):
            raise InvalidUInt32Value(value)
        if value not in range(MIN_UINT32, MAX_UINT32 + 1):
            raise InvalidUInt32Value(value)
        return value

    @property
    def value(self) -> int:
        return self._value

    @value.setter
    def value(self, value) -> None:
        self._value = self._validate_value(value)

    def __eq__(self, obj):
        """
        Compare instances of UInt32 objects
        """
        if isinstance(obj, UInt32):
            return self.value == obj.value
        elif isinstance(obj, int):
            return self.value == obj
        else:
            return False

    def to_asn1(self) -> UInt32Asn1:
        """
        Convert object to ASN1 structure
        """
        return UInt32Asn1(self._value)

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()
