import ipapocket.krb5.constants
import ipapocket.krb5.asn1 as asn1

class PrincipalName():
    def __init__(self, type=None, value=None):
        self._type = type
        self._value = value

    def to_asn1(self):
        return asn1.PrincipalNameAsn1(
            {
                'name-type': self._type,
                'name-string': self._value,
            }
        )
