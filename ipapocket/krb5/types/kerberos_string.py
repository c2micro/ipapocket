from ipapocket.krb5.asn1 import KerberosStringAsn1
from ipapocket.exceptions.krb5 import InvalidKerberosStringValue


class KerberosString:
    _value: str = None

    def __init__(self, value=None):
        self.value = value

    def _validate_value(self, value) -> str:
        if value is None:
            return ""
        elif isinstance(value, str):
            return value
        elif isinstance(value, KerberosString):
            return value.to_asn1().native
        else:
            raise InvalidKerberosStringValue(value)

    @classmethod
    def load(cls, data: KerberosStringAsn1):
        """
        Create object of KerberosString from ASN1 structure
        """
        if isinstance(data, KerberosString):
            data = data.to_asn1()
        return cls(data.native)

    @property
    def value(self) -> str:
        return self._value

    @value.setter
    def value(self, value) -> None:
        self._value = self._validate_value(value)

    def __str__(self) -> str:
        return self._value

    def __eq__(self, obj):
        """
        Compare instances of KerberosString objects
        """
        if isinstance(obj, KerberosString):
            return self.value == obj.value
        elif isinstance(obj, str):
            return self.value == obj
        else:
            return False

    def to_asn1(self) -> KerberosStringAsn1:
        """
        Convert object to ASN1
        """
        return KerberosStringAsn1(self._value)

    def pretty(self):
        """
        Convert object to string
        """
        return self.value

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()
