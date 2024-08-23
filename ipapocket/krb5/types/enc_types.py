from ipapocket.krb5.asn1 import EncTypesAsn1
from ipapocket.exceptions.krb5 import InvalidEncTypesValueType
from ipapocket.krb5.constants import EncryptionType


class EncTypes:
    _etypes: list[EncryptionType] = None

    def __init__(self, etypes):
        self.etypes = etypes

    def _validate_etypes(self, value):
        if isinstance(value, int):
            return [EncryptionType(value)]
        elif isinstance(value, list):
            return value
        elif isinstance(value, EncryptionType):
            return [value]
        else:
            raise InvalidEncTypesValueType(value)

    @classmethod
    def load(cls, data: EncTypesAsn1):
        if isinstance(data, EncTypes):
            data = data.to_asn1()
        tmp = list[EncryptionType]()
        for v in data.native:
            tmp.append(EncryptionType(v))
        return cls(tmp)

    @property
    def etypes(self) -> list[EncryptionType]:
        return self._etypes

    @etypes.setter
    def etypes(self, value) -> None:
        self._etypes = self._validate_etypes(value)

    def to_asn1(self) -> EncTypesAsn1:
        final = list()
        for t in self._etypes:
            final.append(t.value)
        return EncTypesAsn1(final)

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()
