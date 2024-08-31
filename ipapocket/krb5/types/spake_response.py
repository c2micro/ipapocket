from ipapocket.krb5.types.encrypted_data import EncryptedData
from ipapocket.krb5.asn1 import SpakeResponseAsn1
from ipapocket.krb5.constants.fields import SPAKE_RESPONSE_FACTOR, SPAKE_RESPONSE_PUBKEY


class SpakeResponse:
    _pubkey: str = None
    _factor: EncryptedData = None

    @property
    def pubkey(self) -> str:
        return self._pubkey

    @pubkey.setter
    def pubkey(self, value) -> None:
        self._pubkey = value

    @property
    def factor(self) -> EncryptedData:
        return self._factor

    @factor.setter
    def factor(self, value) -> None:
        self._factor = value

    @classmethod
    def load(cls, data: SpakeResponseAsn1):
        if isinstance(data, SpakeResponse):
            data = data.to_asn1()
        tmp = cls()
        if SPAKE_RESPONSE_PUBKEY in data:
            if data[SPAKE_RESPONSE_PUBKEY].native is not None:
                tmp.pubkey = data[SPAKE_RESPONSE_PUBKEY].native
        if SPAKE_RESPONSE_FACTOR in data:
            if data[SPAKE_RESPONSE_FACTOR].native is not None:
                tmp.factor = EncryptedData.load(data[SPAKE_RESPONSE_FACTOR])
        return tmp

    def to_asn1(self) -> SpakeResponseAsn1:
        tmp = SpakeResponseAsn1()
        if self.pubkey is not None:
            tmp[SPAKE_RESPONSE_PUBKEY] = self.pubkey
        if self.factor is not None:
            tmp[SPAKE_RESPONSE_FACTOR] = self.factor.to_asn1()
        return tmp

    def dump(self):
        return self.to_asn1().dump()