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

class KdcOptions():
    def __init__(self, options):
        self._options = options

    def to_asn1(self):
        flags = list()
        for i in range(0, 32):
            flags.append(0,)
        for f in self._options:
            flags[f] = 1
        print(flags)
        return asn1.KdcOptionsAsn1(flags)