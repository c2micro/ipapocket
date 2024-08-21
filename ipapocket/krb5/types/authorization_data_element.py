from ipapocket.krb5.constants import AuthorizationDataTypes


class AuthorizationDataElement:
    _ad_type: AuthorizationDataTypes = None
    _ad_data: str = None

    def __init__(self):
        pass

    @property
    def ad_type(self) -> AuthorizationDataTypes:
        return self._ad_type

    @ad_type.setter
    def ad_type(self, value) -> None:
        self._ad_type = value

    @property
    def ad_data(self) -> str:
        return self._ad_data

    @ad_data.setter
    def ad_data(self, value) -> None:
        self._ad_data = value

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()
