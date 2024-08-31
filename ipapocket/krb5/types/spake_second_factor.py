from ipapocket.krb5.constants import SpakeSecondFactorType
from ipapocket.krb5.asn1 import SpakeSecondFactorAsn1
from ipapocket.krb5.constants.fields import (
    SPAKE_SECOND_FACTOR_TYPE,
    SPAKE_SECOND_FACTOR_DATA,
)


class SpakeSecondFactor:
    _type: SpakeSecondFactorType = None
    _data: str = None

    @property
    def type(self) -> SpakeSecondFactorType:
        return self._type

    @type.setter
    def type(self, value) -> None:
        self._type = value

    @property
    def data(self) -> str:
        return self._data

    @data.setter
    def data(self, value) -> None:
        self._data = value

    @classmethod
    def load(cls, data: SpakeSecondFactorAsn1):
        if isinstance(data, SpakeSecondFactor):
            data = data.to_asn1()
        tmp = cls()
        if SPAKE_SECOND_FACTOR_TYPE in data:
            if data[SPAKE_SECOND_FACTOR_TYPE].native is not None:
                tmp.type = SpakeSecondFactorType(data[SPAKE_SECOND_FACTOR_TYPE].native)
        if SPAKE_SECOND_FACTOR_DATA in data:
            if data[SPAKE_SECOND_FACTOR_DATA].native is not None:
                tmp.data = data[SPAKE_SECOND_FACTOR_DATA].native
        return tmp

    def to_asn1(self) -> SpakeSecondFactorAsn1:
        tmp = SpakeSecondFactorAsn1()
        if self.type is not None:
            tmp[SPAKE_SECOND_FACTOR_TYPE] = self.type.value
        if self.data is not None:
            tmp[SPAKE_SECOND_FACTOR_DATA] = self.data
        return tmp

    def dump(self):
        return self.to_asn1().dump()
