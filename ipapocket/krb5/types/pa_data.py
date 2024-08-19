from ipapocket.krb5.constants import PreAuthenticationDataTypes
from ipapocket.exceptions.krb5 import InvalidPaDataType
from ipapocket.krb5.types.encrypted_data import EncryptedData
from ipapocket.krb5.asn1 import PaDataAsn1
from ipapocket.krb5.fields import PADATA_PADATA_TYPE, PADATA_PADATA_VALUE


class PaData:
    _type: PreAuthenticationDataTypes = None
    _value = None

    def __init__(self, type=None, value=None):
        self._type = type
        self._value = self._validate_value(value)

    @property
    def type(self) -> PreAuthenticationDataTypes:
        return self._type

    @type.setter
    def type(self, value) -> None:
        if not isinstance(value, PreAuthenticationDataTypes):
            raise InvalidPaDataType()
        self._type = value

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, value):
        self._value = self._validate_value(value)

    def _validate_value(self, value):
        if isinstance(value, EncryptedData):
            return value.to_asn1().dump()
        else:
            return value

    @classmethod
    def load(cls, data: PaDataAsn1):
        if isinstance(data, PaData):
            data = data.to_asn1()
        tmp = cls()
        if PADATA_PADATA_TYPE in data:
            if data[PADATA_PADATA_TYPE] is not None:
                tmp.type = PreAuthenticationDataTypes(data[PADATA_PADATA_TYPE])
        if PADATA_PADATA_VALUE in data:
            if data[PADATA_PADATA_VALUE] is not None:
                tmp.value = data[PADATA_PADATA_VALUE]
        return tmp

    def to_asn1(self) -> PaDataAsn1:
        pa_data = PaDataAsn1()
        if self._type is not None:
            pa_data[PADATA_PADATA_TYPE] = self._type.value
        if self._value is not None:
            pa_data[PADATA_PADATA_VALUE] = self._value
        return pa_data

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()
