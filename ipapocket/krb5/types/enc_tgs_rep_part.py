from ipapocket.krb5.types.enc_kdc_rep_part import EncKdcRepPart
from ipapocket.krb5.asn1 import EncTgsRepPartAsn1


class EncTgsRepPart:
    _enc_kdc_rep_part: EncKdcRepPart = None

    def __init__(self, enc_kdc_rep: EncKdcRepPart = None):
        self._enc_kdc_rep_part = enc_kdc_rep

    @property
    def enc_kdc_rep_part(self) -> EncKdcRepPart:
        return self._enc_kdc_rep_part

    @enc_kdc_rep_part.setter
    def enc_kdc_rep_part(self, value) -> None:
        self._enc_kdc_rep_part = value

    @classmethod
    def load(cls, data: EncTgsRepPartAsn1):
        if isinstance(data, bytes):
            data = EncTgsRepPartAsn1.load(data)
        if isinstance(data, EncTgsRepPart):
            data = data.to_asn1()
        return cls(EncKdcRepPart.load(data))

    def to_asn1(self) -> EncTgsRepPartAsn1:
        return EncTgsRepPartAsn1(self._enc_kdc_rep_part)

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()
