from ipapocket.krb5.types.enc_as_rep_part import EncAsRepPart
from ipapocket.krb5.types.enc_tgs_rep_part import EncTgsRepPart
from ipapocket.krb5.asn1 import EncRepPartAsn1
from ipapocket.krb5.fields import ENC_REP_PART_AS_REP, ENC_REP_PART_TGS_REP
from ipapocket.exceptions.krb5 import UnexpectedEncRepPartType


class EncRepPart:
    _enc_as_rep_part: EncAsRepPart = None
    _enc_tgs_rep_part: EncTgsRepPart = None

    def __init__(self):
        pass

    def is_enc_as_rep(self) -> bool:
        return self._enc_as_rep_part is not None

    def is_enc_tgs_rep(self) -> bool:
        return self._enc_tgs_rep_part is not None

    @property
    def enc_as_rep_part(self) -> EncAsRepPart:
        return self._enc_as_rep_part

    @enc_as_rep_part.setter
    def enc_as_rep_part(self, value) -> None:
        self._enc_as_rep_part = value

    @property
    def enc_tgs_rep_part(self) -> EncTgsRepPart:
        return self._enc_tgs_rep_part

    @enc_tgs_rep_part.setter
    def enc_tgs_rep_part(self, value) -> None:
        self._enc_tgs_rep_part = value

    @classmethod
    def load(cls, data: EncRepPartAsn1):
        if isinstance(data, bytes):
            response = EncRepPartAsn1.load(data)
        if response.name == ENC_REP_PART_AS_REP:
            tmp = cls()
            tmp.enc_as_rep_part = EncAsRepPart.load(data)
            return tmp
        elif response.name == ENC_REP_PART_TGS_REP:
            tmp = cls()
            tmp.enc_tgs_rep_part = EncTgsRepPart.load(data)
            return tmp
        else:
            raise UnexpectedEncRepPartType()

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()
