from ipapocket.krb5.constants import AuthorizationDataType
from ipapocket.krb5.asn1 import AuthorizationDataElementAsn1
from ipapocket.krb5.constants.fields import AUTHORIZATION_DATA_AD_TYPE, AUTHORIZATION_DATA_AD_DATA


class AuthorizationDataElement:
    _ad_type: AuthorizationDataType = None
    _ad_data: str = None

    def __init__(self):
        pass

    @property
    def ad_type(self) -> AuthorizationDataType:
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

    @classmethod
    def load(cls, data: AuthorizationDataElementAsn1):
        if isinstance(data, AuthorizationDataElement):
            data = data.to_asn1()
        tmp = cls()
        if AUTHORIZATION_DATA_AD_TYPE in data:
            if data[AUTHORIZATION_DATA_AD_TYPE].native is not None:
                tmp.ad_type = AuthorizationDataType(
                    data[AUTHORIZATION_DATA_AD_TYPE].native
                )
        if AUTHORIZATION_DATA_AD_DATA in data:
            if data[AUTHORIZATION_DATA_AD_DATA].native is not None:
                tmp.ad_data = data[AUTHORIZATION_DATA_AD_DATA].native
        return tmp

    def to_asn1(self) -> AuthorizationDataElementAsn1:
        auth_data_element = AuthorizationDataElementAsn1()
        if self.ad_type is not None:
            auth_data_element[AUTHORIZATION_DATA_AD_TYPE] = self.ad_type.value
        if self.ad_data is not None:
            auth_data_element[AUTHORIZATION_DATA_AD_DATA] = self.ad_data
        return auth_data_element
