from ipapocket.krb5.asn1 import UInt16Asn1
from ipapocket.krb5.constants import MIN_UINT16, MAX_UINT16
from ipapocket.exceptions.krb5 import InvalidUInt16Value
import enum


class UInt16:
    _value: int = 0

    def __init__(self, value=None):
        self.value = value

    @classmethod
    def load(cls, data: UInt16Asn1):
        """
        Create object of UInt16 from ASN1 structure
        """
        if isinstance(data, UInt16):
            data = data.to_asn1()
        if isinstance(data, int):
            return cls(data)
        return cls(data.native)

    def _validate_value(self, value) -> int:
        if value is None:
            return 0
        if isinstance(value, UInt16):
            return value.value
        if isinstance(value, enum.Enum):
            value = value.value
        if not isinstance(value, int):
            raise InvalidUInt16Value(value)
        if value not in range(MIN_UINT16, MAX_UINT16 + 1):
            raise InvalidUInt16Value(value)
        return value

    @property
    def value(self) -> int:
        return self._value

    @value.setter
    def value(self, value) -> None:
        self._value = self._validate_value(value)

    def __eq__(self, obj):
        """
        Compare instances of UInt16 objects
        """
        if isinstance(obj, UInt16):
            return self.value == obj.value
        elif isinstance(obj, int):
            return self.value == obj
        else:
            return False

    def to_asn1(self) -> UInt16Asn1:
        """
        Convert object to ASN1 structure
        """
        return UInt16Asn1(self._value)

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()
