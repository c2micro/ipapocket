from ipapocket.exceptions.krb5 import InvalidEncTypesValueType
from ipapocket.krb5.types.pa_data import PaData
from ipapocket.krb5.asn1 import MethodDataAsn1


class MethodData:
    _padatas: list = None

    def __init__(self):
        self._padatas = list()

    def add(self, padata):
        if not isinstance(padata, PaData):
            raise InvalidEncTypesValueType()
        self._padatas.append(padata)

    def clear(self):
        self._padatas = list()

    @property
    def padatas(self) -> list:
        return self._padatas

    @classmethod
    def load(cls, data: MethodDataAsn1):
        if isinstance(data, bytes):
            data = MethodDataAsn1.load(data)
        if isinstance(data, MethodData):
            data = data.to_asn1()
        tmp = cls()
        for v in data.native:
            tmp.add(PaData.load(v))
        return tmp

    def to_asn1(self):
        tmp = list()
        for pa_data in self._padatas:
            tmp.append(pa_data.to_asn1())
        return MethodDataAsn1(tuple(tmp))

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()
