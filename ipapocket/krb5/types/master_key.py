from ipapocket.krb5.asn1 import MasterKeyAsn1
from ipapocket.krb5.constants import EncryptionTypes
from ipapocket.exceptions.krb5 import InvalidMasterKeyTypeAlgo
from ipapocket.krb5.fields import MASTER_KEY_KEYTYPE, MASTER_KEY_KEYVALUE


class MasterKey:
    _keytype: EncryptionTypes = None
    _keyvalue: str = None

    @property
    def keytype(self) -> EncryptionTypes:
        return self._keytype

    @keytype.setter
    def keytype(self, value) -> None:
        if isinstance(value, int):
            self._keytype = EncryptionTypes(value)
        elif isinstance(value, EncryptionTypes):
            self._keytype = value
        else:
            raise InvalidMasterKeyTypeAlgo()

    @property
    def keyvalue(self) -> str:
        return self._keyvalue

    @keyvalue.setter
    def keyvalue(self, value) -> None:
        self._keyvalue = value

    @classmethod
    def load(cls, data: MasterKeyAsn1):
        if isinstance(data, MasterKey):
            data = data.to_asn1()
        tmp = cls()
        if MASTER_KEY_KEYTYPE in data:
            if data[MASTER_KEY_KEYTYPE].native is not None:
                tmp.keytype = EncryptionTypes(data[MASTER_KEY_KEYTYPE].native)
        if MASTER_KEY_KEYVALUE in data:
            if data[MASTER_KEY_KEYVALUE].native is not None:
                tmp.keyvalue = data[MASTER_KEY_KEYVALUE].native
        return tmp

    def to_asn1(self) -> MasterKeyAsn1:
        master_key = MasterKeyAsn1()
        if self.keytype is not None:
            master_key[MASTER_KEY_KEYTYPE] = self.keytype.value
        if self.keyvalue is not None:
            master_key[MASTER_KEY_KEYVALUE] = self.keyvalue
        return master_key
