from ipapocket.krb5.asn1 import TicketFlagsAsn1
from ipapocket.exceptions.krb5 import InvalidTicketFlagsValueType
from ipapocket.krb5.types.kerberos_flags import KerberosFlags
from ipapocket.krb5.constants import TicketFlagsType


class TicketFlags:
    _flags: KerberosFlags = None

    def __init__(self):
        self._flags = KerberosFlags()

    def add(self, flag):
        self._flags.add(self._validate_option(flag))

    def clear(self):
        self._flags.clear()

    @property
    def flags(self):
        return self._flags.flags

    @classmethod
    def load(cls, value: TicketFlagsAsn1):
        if isinstance(value, TicketFlags):
            value = value.to_asn1()
        tmp = cls()
        for i in range(len(value.native)):
            if value.native[i] == 1:
                tmp.add(TicketFlagsType(i))
        return tmp

    def _validate_option(self, value) -> TicketFlagsType:
        if not isinstance(value, TicketFlagsType):
            raise InvalidTicketFlagsValueType(value)
        return value

    def to_asn1(self) -> TicketFlagsAsn1:
        return TicketFlagsAsn1(self._flags.to_asn1().native)

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()
