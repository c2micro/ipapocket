from ipapocket.krb5.types.kerberos_flags import KerberosFlags
from ipapocket.krb5.constants import ApOptionsType
from ipapocket.krb5.asn1 import ApOptionsAsn1
from ipapocket.exceptions.krb5 import InvalidApOptionsValueType


class ApOptions:
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
    def load(cls, value: ApOptionsAsn1):
        if isinstance(value, ApOptions):
            value = value.to_asn1()
        tmp = cls()
        for v in value.native:
            if v == 1:
                tmp.add(ApOptionsType(v))
        return tmp

    def _validate_option(self, value) -> ApOptionsType:
        if not isinstance(value, ApOptionsType):
            raise InvalidApOptionsValueType(value)
        return value

    def to_asn1(self) -> ApOptionsAsn1:
        return ApOptionsAsn1(self._options.to_asn1().native)

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()
