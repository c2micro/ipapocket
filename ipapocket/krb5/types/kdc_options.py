from ipapocket.krb5.asn1 import KdcOptionsAsn1
from ipapocket.exceptions.krb5 import InvalidKdcOptionsValueType
from ipapocket.krb5.types.kerberos_flags import KerberosFlags
from ipapocket.krb5.constants import KdcOptionsType


class KdcOptions:
    _options: KerberosFlags = None

    def __init__(self):
        self._options = KerberosFlags()

    def add(self, option):
        self._options.add(self._validate_option(option))

    def clear(self):
        self._options.clear()

    @property
    def options(self):
        return self._options.flags

    @classmethod
    def load(cls, value: KdcOptionsAsn1):
        if isinstance(value, KdcOptions):
            value = value.to_asn1()
        tmp = cls()
        for v in value.native:
            if v == 1:
                tmp.add(KdcOptionsType(v))
        return tmp

    def _validate_option(self, value) -> KdcOptionsType:
        if not isinstance(value, KdcOptionsType):
            raise InvalidKdcOptionsValueType(value)
        return value

    def to_asn1(self) -> KdcOptionsAsn1:
        return KdcOptionsAsn1(self._options.to_asn1().native)

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()
