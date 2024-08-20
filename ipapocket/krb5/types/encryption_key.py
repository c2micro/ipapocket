from ipapocket.krb5.constants import EncryptionTypes
from ipapocket.krb5.asn1 import EncryptionKeyAsn1
from ipapocket.krb5.fields import ENCRYPTION_KEY_KEYTYPE, ENCRYPTION_KEY_KEYVALUE


class EncryptionKey:
    _keytype: EncryptionTypes = None
    _keyvalue: str = None

    def __init__(self):
        pass

    @property
    def keytype(self) -> EncryptionTypes:
        return self._keytype

    @keytype.setter
    def keytype(self, value) -> None:
        self._keytype = value

    @property
    def keyvalue(self) -> str:
        return self._keyvalue

    @keyvalue.setter
    def keyvalue(self, value) -> None:
        self._keyvalue = value

    @classmethod
    def load(cls, data: EncryptionKeyAsn1):
        if isinstance(data, EncryptionKey):
            data = data.to_asn1()
        tmp = cls()
        if ENCRYPTION_KEY_KEYTYPE in data:
            if data[ENCRYPTION_KEY_KEYTYPE].native is not None:
                tmp.keytype = EncryptionTypes(data[ENCRYPTION_KEY_KEYTYPE].native)
        if ENCRYPTION_KEY_KEYVALUE in data:
            if data[ENCRYPTION_KEY_KEYVALUE].native is not None:
                tmp.keyvalue = data[ENCRYPTION_KEY_KEYVALUE].native
        return tmp

    def to_asn1(self) -> EncryptionKeyAsn1:
        enc_key = EncryptionKeyAsn1()
        if self._keytype is not None:
            enc_key[ENCRYPTION_KEY_KEYTYPE] = self._keytype.value
        if self._keyvalue is not None:
            enc_key[ENCRYPTION_KEY_KEYVALUE] = self._keyvalue
        return enc_key

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()
