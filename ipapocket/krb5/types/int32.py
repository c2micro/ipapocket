from ipapocket.krb5.asn1 import Int32Asn1
from ipapocket.krb5.constants import MIN_INT32, MAX_INT32
from ipapocket.exceptions.krb5 import InvalidInt32Value
import enum


class Int32:
    _value: int = 0

    def __init__(self, value=None):
        self.value = value

    def _validate_value(self, value) -> int:
        if value is None:
            return 0
        if isinstance(value, Int32):
            return value.value
        if isinstance(value, enum.Enum):
            value = value.value
        if not isinstance(value, int):
            raise InvalidInt32Value(value)
        if value not in range(MIN_INT32, MAX_INT32 + 1):
            raise InvalidInt32Value(value)
        return value

    @property
    def value(self) -> int:
        return self._value

    @value.setter
    def value(self, value: int) -> None:
        self._value = self._validate_value(value)

    def __eq__(self, obj):
        """
        Compare instances of Int32 objects
        """
        if isinstance(obj, Int32):
            return self.value == obj.value
        elif isinstance(obj, int):
            return self.value == obj
        else:
            return False

    @classmethod
    def load(cls, data: Int32Asn1):
        """
        Create object of Int32 from ASN1 structure
        """
        if isinstance(data, Int32):
            data = data.to_asn1()
        if isinstance(data, int):
            return cls(data)
        return cls(data.native)

    def to_asn1(self) -> Int32Asn1:
        """
        Convert object to ASN1 structure
        """
        return Int32Asn1(self._value)

    def pretty(self):
        """
        Convert object to value
        """
        return self.value

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()
