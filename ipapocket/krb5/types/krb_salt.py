from ipapocket.krb5.constants import KdbSaltTypes
from ipapocket.exceptions.krb5 import InvalidSaltType
from ipapocket.krb5.asn1 import KrbSaltAsn1
from ipapocket.krb5.fields import KRB_SALT_TYPE, KRB_SALT_SALT


class KrbSalt:
    _type: KdbSaltTypes = None
    _salt: str = None

    @property
    def type(self) -> KdbSaltTypes:
        return self._type

    @type.setter
    def type(self, value) -> None:
        if isinstance(value, int):
            self._type = KdbSaltTypes(value)
        elif isinstance(value, KdbSaltTypes):
            self._type = value
        else:
            raise InvalidSaltType()

    @property
    def salt(self) -> str:
        return self._salt

    @salt.setter
    def salt(self, value) -> None:
        self._salt = value

    @classmethod
    def load(cls, data: KrbSaltAsn1):
        if isinstance(data, KrbSalt):
            data = data.to_asn1()
        tmp = cls()
        if KRB_SALT_TYPE in data:
            if data[KRB_SALT_TYPE].native is not None:
                tmp.type = KdbSaltTypes(data[KRB_SALT_TYPE].native)
        if KRB_SALT_SALT in data:
            if data[KRB_SALT_SALT].native is not None:
                tmp.salt = data[KRB_SALT_SALT].native
        return tmp

    def to_asn1(self) -> KrbSaltAsn1:
        krb_salt = KrbSaltAsn1()
        if self.type is not None:
            krb_salt[KRB_SALT_TYPE] = self.type.value
        if self.salt is not None:
            krb_salt[KRB_SALT_SALT] = self.salt
        return krb_salt
