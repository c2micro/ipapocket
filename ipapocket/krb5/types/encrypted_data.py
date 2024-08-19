from ipapocket.krb5.types.uint32 import UInt32
from ipapocket.krb5.types.int32 import Int32
from ipapocket.krb5.constants import EncryptionTypes
from ipapocket.krb5.asn1 import EncryptedDataAsn1
from ipapocket.krb5.fields import (
    ENCRYPTED_DATA_CIPHER,
    ENCRYPTED_DATA_ETYPE,
    ENCRYPTED_DATA_KVNO,
)


class EncryptedData:
    _etype: EncryptionTypes = None
    _kvno: UInt32 = None
    _cipher = None

    def __init__(self, etype=None, kvno=None, cipher=None):
        self.etype = etype
        self._kvno = self._validate_kvno(kvno)
        self._cipher = cipher

    def _validate_etype(self, value):
        if value is None:
            return None
        if isinstance(value, int):
            return EncryptionTypes(value)
        elif isinstance(value, EncryptionTypes):
            return value
        elif isinstance(value, Int32):
            return EncryptionTypes(value.value)
        else:
            raise

    def _validate_kvno(self, value):
        return UInt32(value)

    @classmethod
    def load(cls, data: EncryptedDataAsn1):
        if isinstance(data, EncryptedData):
            data = data.to_asn1()
        tmp = cls()
        if ENCRYPTED_DATA_ETYPE in data:
            if data[ENCRYPTED_DATA_ETYPE].native is not None:
                tmp.etype = EncryptionTypes(
                    Int32.load(data[ENCRYPTED_DATA_ETYPE]).value
                )
        if ENCRYPTED_DATA_KVNO in data:
            if data[ENCRYPTED_DATA_KVNO].native is not None:
                tmp.kvno = UInt32.load(data[ENCRYPTED_DATA_KVNO])
        if ENCRYPTED_DATA_CIPHER in data:
            tmp.cipher = data[ENCRYPTED_DATA_CIPHER].native
        return tmp

    @property
    def etype(self) -> EncryptionTypes:
        return self._etype

    @etype.setter
    def etype(self, value) -> None:
        self._etype = self._validate_etype(value)

    @property
    def kvno(self) -> UInt32:
        return self._kvno

    @kvno.setter
    def kvno(self, value) -> None:
        self._kvno = self._validate_kvno(value)

    @property
    def cipher(self):
        return self._cipher

    @cipher.setter
    def cipher(self, value) -> None:
        self._cipher = value

    def to_asn1(self) -> EncryptedDataAsn1:
        enc_data = EncryptedDataAsn1()
        if self._etype is not None:
            enc_data[ENCRYPTED_DATA_ETYPE] = self._etype.value
        if self._kvno is not None:
            enc_data[ENCRYPTED_DATA_KVNO] = self._kvno.to_asn1()
        if self._cipher is not None:
            enc_data[ENCRYPTED_DATA_CIPHER] = self._cipher
        return enc_data

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()
