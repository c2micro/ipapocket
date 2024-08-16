from ipapocket.krb5.asn1 import MicrosecondsAsn1
from ipapocket.krb5.constants import MIN_MICROSECONDS, MAX_MICROSECONDS
from ipapocket.exceptions.krb5 import InvalidMicrosecondsValue


class Microseconds:
    _value: int = 0

    def __init__(self, value=None):
        self.value = value

    @classmethod
    def load(cls, data: MicrosecondsAsn1):
        """
        Create object of Microseconds from ASN1 structure
        """
        if isinstance(data, Microseconds):
            data = data.to_asn1()
        if isinstance(data, int):
            return cls(data)
        return cls(data.native)

    def _validate_value(self, value) -> int:
        if value is None:
            value = 0
        if isinstance(value, Microseconds):
            return value.value
        if not isinstance(value, int):
            raise InvalidMicrosecondsValue(value)
        if value not in range(MIN_MICROSECONDS, MAX_MICROSECONDS + 1):
            raise InvalidMicrosecondsValue(value)
        return value

    @property
    def value(self) -> int:
        return self._value

    @value.setter
    def value(self, value: int) -> None:
        self._value = self._validate_value(value)

    def __eq__(self, obj):
        """
        Compare instances of Microseconds objects
        """
        if isinstance(obj, Microseconds):
            return self.value == obj.value
        elif isinstance(obj, int):
            return self.value == obj
        else:
            return False

    def to_asn1(self) -> MicrosecondsAsn1:
        """
        Convert object to ASN1 structure
        """
        return MicrosecondsAsn1(self._value)

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()
