import ipapocket.krb5.constants
import ipapocket.krb5.asn1 as asn1
from bitarray import bitarray

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
    def __init__(self):
        self._options = list()

    def add(self, option):
        self._options.append(option)

    def to_asn1(self):
        b_arr = bitarray(32)
        for option in self._options:
            b_arr[option.value] = 1
        return asn1.KdcOptionsAsn1(tuple(b_arr.tolist()))


class KdcReqBody():
    def __init__(self):
        self._kdcOptions = None

    def setKdcOptions(self, options):
        self._kdcOptions = options

    def to_asn1(self):
        kdcReqBody = asn1.KdcReqBodyAsn1()
        if self._kdcOptions is not None:
            kdcReqBody['kdc-options'] = self._kdcOptions.to_asn1(),
        return kdcReqBody