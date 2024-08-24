from datetime import datetime
from ipapocket.krb5.asn1 import KerberosTimeAsn1
from ipapocket.exceptions.krb5 import InvalidKerberosTimeValueType


class KerberosTime:
    _time: datetime = None

    def __init__(self, ktime: datetime):
        self.time = ktime

    def _validate_time(self, ktime):
        if not isinstance(ktime, datetime):
            raise InvalidKerberosTimeValueType(ktime)
        # we must remove microseconds from time (RFC note)
        return ktime.replace(microsecond=0)

    @property
    def time(self) -> datetime:
        return self._time

    @time.setter
    def time(self, value) -> None:
        self._time = self._validate_time(value)

    @classmethod
    def load(cls, data: KerberosTimeAsn1):
        if isinstance(data, KerberosTime):
            data = data.to_asn1()
        return cls(data.native)

    def to_asn1(self) -> KerberosTimeAsn1:
        return KerberosTimeAsn1(self._time)

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()
