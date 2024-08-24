from ipapocket.krb5.types.krb_cred_info import KrbCredInfo
from ipapocket.krb5.asn1 import KrbCredInfosAsn1


class KrbCredInfos:
    _creds: list[KrbCredInfo] = None

    def __init__(self):
        self._creds = list()

    @property
    def keys(self) -> list[KrbCredInfo]:
        return self._creds

    def add(self, value):
        self._creds.append(value)

    def clear(self):
        self._creds = list()

    @classmethod
    def load(cls, data: KrbCredInfosAsn1):
        if isinstance(data, KrbCredInfos):
            data = data.to_asn1()
        tmp = cls()
        for v in data:
            tmp.add(KrbCredInfo.load(v))
        return tmp

    def to_asn1(self) -> KrbCredInfosAsn1:
        tmp = list()
        for v in self._creds:
            tmp.append(v.to_asn1())
        return KrbCredInfosAsn1(tmp)

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()
