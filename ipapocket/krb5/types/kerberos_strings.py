from ipapocket.krb5.asn1 import KerberosStringsAsn1
from ipapocket.exceptions.krb5 import InvalidKerberosStringsValue
from ipapocket.krb5.types.kerberos_string import KerberosString


class KerberosStrings:
    _value: list[KerberosString] = None

    def __init__(self, value=None):
        self.value = value

    @classmethod
    def load(cls, data: KerberosStringsAsn1):
        """
        Create object of KerberosStrings from ASN1 structure
        """
        if isinstance(data, KerberosStrings):
            data = data.to_asn1()
        return cls(data.native)

    def _validate_value(self, value) -> list:
        if value is None:
            return list[KerberosString]()
        if isinstance(value, str):
            return [KerberosString(value)]
        elif isinstance(value, list):
            tmp = list()
            for v in value:
                tmp.append(KerberosString(v))
            return tmp
        elif isinstance(value, KerberosString):
            return [value]
        elif isinstance(value, KerberosStrings):
            tmp = list()
            for v in value.to_asn1().native:
                tmp.append(KerberosString(v))
            return tmp
        else:
            raise InvalidKerberosStringsValue(value)

    @property
    def value(self) -> list[KerberosString]:
        return self._value

    @value.setter
    def value(self, value) -> None:
        self._value = self._validate_value(value)

    def __eq__(self, obj):
        """
        Compare instances of KerberosStrings objects
        """
        if isinstance(obj, KerberosStrings):
            return self.value == obj.value
        elif isinstance(obj, list):
            return self.value == obj
        else:
            return False
    
    def __str__(self) -> str:
        tmp = ""
        for i in range(len(self.value)):
            if i == len(self.value) - 1:
                tmp += self.value[i].value
            else:
                tmp += self.value[i].value + "/"
        return tmp

    def to_asn1(self) -> KerberosStringsAsn1:
        """
        Convert object to ASN1 structure
        """
        tmp = list()
        for v in self._value:
            tmp.append(v.to_asn1())
        return KerberosStringsAsn1(tmp)

    def pretty(self):
        """
        Convert object to list of values
        """
        tmp = list()
        for v in self.value:
            tmp.append(v.pretty())
        return tmp

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()
