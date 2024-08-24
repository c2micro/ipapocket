from ipapocket.krb5.types.etype_info2_entry import EtypeInfo2Entry
from ipapocket.krb5.asn1 import EtypeInfo2Asn1


class EtypeInfo2:
    _entries: list[EtypeInfo2Entry] = list[EtypeInfo2Entry]()

    def __init__(self):
        self.clear()

    def add(self, value):
        self._entries.append(value)

    def clear(self) -> None:
        self._entries.clear()

    @property
    def entries(self) -> list[EtypeInfo2Entry]:
        return self._entries

    @classmethod
    def load(cls, data: EtypeInfo2Asn1):
        if isinstance(data, bytes):
            data = EtypeInfo2Asn1.load(data)
        if isinstance(data, EtypeInfo2):
            data = data.to_asn1()
        tmp = cls()
        for v in data:
            tmp.add(EtypeInfo2Entry.load(v))
        return tmp

    def to_asn1(self) -> EtypeInfo2Asn1:
        tmp = list()
        for v in self._entries:
            tmp.append(v.to_asn1())
        return EtypeInfo2Asn1(tmp)

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()
