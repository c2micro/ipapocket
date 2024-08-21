from ipapocket.krb5.types.authorization_data_element import AuthorizationDataElement
from ipapocket.krb5.asn1 import AuthorizationDataAsn1


class AuthorizationData:
    _elements: list[AuthorizationDataElement] = None

    def __init__(self):
        self._elements = list()

    def add(self, value):
        self._elements.append(value)

    @property
    def elements(self) -> list[AuthorizationDataElement]:
        return self._elements

    @classmethod
    def load(cls, data: AuthorizationDataAsn1):
        if isinstance(data, AuthorizationData):
            data = data.to_asn1()
        tmp = cls()
        for v in data:
            tmp.add(AuthorizationDataElement.load(v))
        return tmp

    def to_asn1(self) -> AuthorizationDataAsn1:
        tmp = list()
        for v in self.elements:
            tmp.append(v.to_asn1())
        return AuthorizationDataAsn1(tmp)

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()
