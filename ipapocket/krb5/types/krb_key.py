from ipapocket.krb5.types.krb_salt import KrbSalt
from ipapocket.krb5.types.encryption_key import EncryptionKey
from ipapocket.krb5.asn1 import KrbKeyAsn1
from ipapocket.krb5.fields import KRB_KEY_KEY, KRB_KEY_S2KPARAMS, KRB_KEY_SALT


class KrbKey:
    _salt: KrbSalt = None
    _key: EncryptionKey = None
    _s2kparams: str = None

    @property
    def salt(self) -> KrbSalt:
        return self._salt

    @salt.setter
    def salt(self, value) -> None:
        self._salt = value

    @property
    def key(self) -> EncryptionKey:
        return self._key

    @key.setter
    def key(self, value) -> None:
        self._key = value

    @property
    def s2kparams(self) -> str:
        return self._s2kparams

    @s2kparams.setter
    def s2kparams(self, value) -> None:
        self._s2kparams = value

    @classmethod
    def load(cls, data: KrbKeyAsn1):
        if isinstance(data, KrbKey):
            data = data.to_asn1()
        tmp = cls()
        if KRB_KEY_SALT in data:
            if data[KRB_KEY_SALT].native is not None:
                tmp.salt = KrbSalt.load(data[KRB_KEY_SALT])
        if KRB_KEY_KEY in data:
            if data[KRB_KEY_KEY].native is not None:
                tmp.key = EncryptionKey.load(data[KRB_KEY_KEY])
        if KRB_KEY_S2KPARAMS in data:
            if data[KRB_KEY_S2KPARAMS].native is not None:
                tmp.s2kparams = data[KRB_KEY_S2KPARAMS].native
        return tmp

    def to_asn1(self) -> KrbKeyAsn1:
        krb_key = KrbKeyAsn1()
        if self.salt is not None:
            krb_key[KRB_KEY_SALT] = self.salt.to_asn1()
        if self.key is not None:
            krb_key[KRB_KEY_KEY] = self.key.to_asn1()
        if self.s2kparams is not None:
            krb_key[KRB_KEY_S2KPARAMS] = self.s2kparams
        return krb_key
