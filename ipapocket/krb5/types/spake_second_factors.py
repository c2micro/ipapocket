from ipapocket.krb5.types.spake_second_factor import SpakeSecondFactor
from ipapocket.krb5.asn1 import SpakeSecondFactorsAsn1
from ipapocket.exceptions.krb5 import InvalidSpakeSecondFactorsType


class SpakeSecondFactors:
    _factors: list[SpakeSecondFactor] = list[SpakeSecondFactor]()

    def __init__(self):
        self.clear()

    def add(self, factor):
        if not isinstance(factor, SpakeSecondFactor):
            raise InvalidSpakeSecondFactorsType(factor)
        self._factors.append(factor)

    def clear(self):
        self._factors = list[SpakeSecondFactor]()

    @property
    def factors(self) -> list[SpakeSecondFactor]:
        return self._factors

    @classmethod
    def load(cls, data: SpakeSecondFactorsAsn1):
        if isinstance(data, bytes):
            data = SpakeSecondFactorsAsn1.load(data)
        if isinstance(data, SpakeSecondFactors):
            data = data.to_asn1()
        tmp = cls()
        for v in data:
            tmp.add(SpakeSecondFactor.load(v))
        return tmp

    def to_asn1(self):
        tmp = list()
        for factor in self._factors:
            tmp.append(factor.to_asn1())
        return SpakeSecondFactorsAsn1(tuple(tmp))

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()
