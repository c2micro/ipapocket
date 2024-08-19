from ipapocket.krb5.types.kerberos_time import KerberosTime
from ipapocket.krb5.types.microseconds import Microseconds
from datetime import datetime
from ipapocket.exceptions.krb5 import (
    InvalidPaEncTsEncPatimestamp,
    InvalidPaEncTsEncPausec,
)
from ipapocket.krb5.asn1 import PaEncTsEncAsn1
from ipapocket.krb5.fields import PA_ENC_TS_ENC_PA_TIMESTAMP, PA_ENC_TS_ENC_PA_USEC


class PaEncTsEnc:
    _patimestamp: KerberosTime = None
    _pausec: Microseconds = None

    def __init__(self, timestamp=None, micros=None):
        self._patimestamp = self._validate_patimestamp(timestamp)
        self._pausec = self._validate_pausec(micros)

    def _validate_patimestamp(self, value):
        if value is None:
            return None
        if isinstance(value, datetime):
            return KerberosTime(value)
        elif isinstance(value, KerberosTime):
            return value
        else:
            raise InvalidPaEncTsEncPatimestamp()

    def _validate_pausec(self, value):
        if value is None:
            return None
        if isinstance(value, int):
            return Microseconds(value)
        elif isinstance(value, Microseconds):
            return value
        else:
            raise InvalidPaEncTsEncPausec()

    @property
    def patimestamp(self) -> KerberosTime:
        return self._patimestamp

    @patimestamp.setter
    def patimestamp(self, value) -> None:
        self._patimestamp = self._validate_patimestamp(value)

    @property
    def pausec(self) -> Microseconds:
        return self._pausec

    @pausec.setter
    def pausec(self, value) -> None:
        self._pausec = self._validate_pausec(value)

    @classmethod
    def load(cls, data: PaEncTsEncAsn1):
        """
        Create object of PaEncTsEnc from ASN1 structure
        """
        if isinstance(data, PaEncTsEnc):
            data = data.to_asn1()
        tmp = cls()
        if PA_ENC_TS_ENC_PA_TIMESTAMP in data:
            if data[PA_ENC_TS_ENC_PA_TIMESTAMP].native is not None:
                tmp.patimestamp = KerberosTime.load(data[PA_ENC_TS_ENC_PA_TIMESTAMP])
        if PA_ENC_TS_ENC_PA_USEC in data:
            if data[PA_ENC_TS_ENC_PA_USEC].native is not None:
                tmp.pausec = Microseconds.load(data[PA_ENC_TS_ENC_PA_USEC])
        return tmp

    def to_asn1(self):
        """
        Convert object to ASN1 structure
        """
        pa_enc_ts_enc = PaEncTsEncAsn1()
        if self._patimestamp is not None:
            pa_enc_ts_enc[PA_ENC_TS_ENC_PA_TIMESTAMP] = self._patimestamp.to_asn1()
        if self._pausec is not None:
            pa_enc_ts_enc[PA_ENC_TS_ENC_PA_USEC] = self._pausec.to_asn1()
        return pa_enc_ts_enc

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()
