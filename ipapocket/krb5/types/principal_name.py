from ipapocket.krb5.asn1 import PrincipalNameAsn1
from ipapocket.exceptions.krb5 import InvalidPrincipalNameType
from ipapocket.krb5.types.kerberos_strings import KerberosStrings
from ipapocket.krb5.constants.fields import PRINCIPAL_NAME_NAME_TYPE, PRINCIPAL_NAME_NAME_STRING
from ipapocket.krb5.constants import NameType


class PrincipalName:
    _type: NameType = None
    _value: KerberosStrings = None

    def __init__(self, type: NameType = None, value=None):
        self.name_type = type
        self.name_value = value

    @classmethod
    def load(cls, data: PrincipalNameAsn1):
        """
        Create object of PrincipalName from ASN1 structure
        """
        if isinstance(data, PrincipalName):
            data = data.to_asn1()
        tmp = cls()
        if PRINCIPAL_NAME_NAME_TYPE in data:
            if data[PRINCIPAL_NAME_NAME_TYPE].native is not None:
                tmp.name_type = NameType(data[PRINCIPAL_NAME_NAME_TYPE].native)
        if PRINCIPAL_NAME_NAME_STRING in data:
            if data[PRINCIPAL_NAME_NAME_STRING].native is not None:
                tmp.name_value = KerberosStrings.load(data[PRINCIPAL_NAME_NAME_STRING])
        return tmp

    @property
    def name_type(self) -> NameType:
        return self._type

    @property
    def name_value(self):
        return self._value

    @name_type.setter
    def name_type(self, type: NameType) -> None:
        self._type = self._validate_type(type)

    @name_value.setter
    def name_value(self, value) -> None:
        self._value = self._validate_value(value)

    def _validate_type(self, value) -> NameType:
        if value is None:
            return None
        if not isinstance(value, NameType):
            raise InvalidPrincipalNameType(value)
        return value

    def _validate_value(self, value) -> KerberosStrings:
        if isinstance(value, str):
            # e.g. admin@ipa.test (we are dropping part after @)
            value = value.split("@")[0]
            # e.g. krbtgt/ipa.test
            value = value.split("/")
        return KerberosStrings(value)

    def __eq__(self, obj):
        if isinstance(obj, PrincipalName):
            return self.name_type == obj.name_type and self.name_value == obj.name_value
        else:
            return False

    def to_asn1(self) -> PrincipalNameAsn1:
        """
        Convert object to ASN1 structure
        """
        principal_name = PrincipalNameAsn1()
        if self._type is not None:
            principal_name[PRINCIPAL_NAME_NAME_TYPE] = self._type.value
        if self._value is not None:
            principal_name[PRINCIPAL_NAME_NAME_STRING] = self._value.to_asn1()
        return principal_name

    def pretty(self):
        """
        Convert object to dict
        """
        tmp = {}
        if self.name_type is not None:
            tmp[PRINCIPAL_NAME_NAME_TYPE] = self.name_type.name
        else:
            tmp[PRINCIPAL_NAME_NAME_TYPE] = None
        if self.name_value is not None:
            tmp[PRINCIPAL_NAME_NAME_STRING] = self.name_value.pretty()
        else:
            tmp[PRINCIPAL_NAME_NAME_STRING] = None
        return tmp

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()
