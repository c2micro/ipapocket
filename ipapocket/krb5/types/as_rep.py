from ipapocket.krb5.types.kdc_rep import KdcRep
from ipapocket.krb5.asn1 import AsRepAsn1


class AsRep:
    _kdc_rep: KdcRep = None

    def __init__(self, kdc_rep: KdcRep = None):
        self._kdc_rep = kdc_rep

    @property
    def kdc_rep(self) -> KdcRep:
        return self._kdc_rep

    @kdc_rep.setter
    def kdc_rep(self, value) -> None:
        self._kdc_rep = value

    @classmethod
    def load(cls, data: AsRepAsn1):
        if isinstance(data, AsRep):
            data = data.to_asn1()
        return cls(KdcRep.load(data))

    def to_asn1(self) -> AsRepAsn1:
        return AsRepAsn1(self._kdc_rep)

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()
