from ipapocket.krb5.types.krb_key import KrbKey
from ipapocket.krb5.asn1 import KrbKeysAsn1


class KrbKeys:
    _keys: list[KrbKey] = None

    def __init__(self):
        self._keys = list()
    
    @property
    def keys(self) -> list[KrbKey]:
        return self._keys

    def add(self, value):
        self._keys.append(value)

    def clear(self):
        self._keys = list()

    @classmethod
    def load(cls, data: KrbKeysAsn1):
        if isinstance(data, KrbKeys):
            data = data.to_asn1()
        tmp = cls()
        for v in data:
            tmp.add(KrbKey.load(v))
        return tmp

    def to_asn1(self) -> KrbKeysAsn1:
        tmp = list()
        for v in self._keys:
            tmp.append(v.to_asn1())
        return KrbKeysAsn1(tmp)

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()
