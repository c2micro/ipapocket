from ipapocket.krb5.types.etype_info_entry import EtypeInfoEntry
from ipapocket.krb5.asn1 import EtypeInfoAsn1


class EtypeInfo:
    _entries: list[EtypeInfoEntry] = None

    def __init__(self):
        self._entries = list()

    def add(self, value):
        self._entries.append(value)

    @classmethod
    def load(cls, data: EtypeInfoAsn1):
        if isinstance(data, bytes):
            data = EtypeInfoAsn1.load(data)
        if isinstance(data, EtypeInfo):
            data = data.to_asn1()
        tmp = cls()
        for v in data:
            tmp.add(EtypeInfoEntry.load(v))
        return tmp

    def to_asn1(self) -> EtypeInfoAsn1:
        tmp = list()
        for v in self._entries:
            tmp.append(v.to_asn1())
        return EtypeInfoAsn1(tmp)

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()
