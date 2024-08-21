from ipapocket.krb5.constants import ChecksumTypes
from ipapocket.krb5.asn1 import ChecksumAsn1
from ipapocket.krb5.fields import CHECKSUM_CHECKSUM, CHECKSUM_CKSUMTYPE


class Checksum:
    _cksumtype: ChecksumTypes = None
    _checksum: str = None

    def __init__(self):
        pass

    @property
    def cksumtype(self) -> ChecksumTypes:
        return self._cksumtype

    @cksumtype.setter
    def cksumtype(self, value) -> None:
        self._cksumtype = value

    @property
    def checksum(self) -> str:
        return self._checksum

    @checksum.setter
    def checksum(self, value) -> None:
        self._checksum = value

    def to_asn1(self) -> ChecksumAsn1:
        checksum = ChecksumAsn1()
        if self.cksumtype is not None:
            checksum[CHECKSUM_CKSUMTYPE] = self.cksumtype.value
        if self.checksum is not None:
            checksum[CHECKSUM_CHECKSUM] = self._checksum
        return checksum

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()
