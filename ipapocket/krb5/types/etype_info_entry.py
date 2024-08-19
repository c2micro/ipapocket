from ipapocket.krb5.constants import EncryptionTypes
from ipapocket.krb5.asn1 import EtypeInfoEntryAsn1
from ipapocket.krb5.fields import ETYPE_INFO_ETYPE, ETYPE_INFO_SALT


class EtypeInfoEntry:
    _etype: EncryptionTypes = None
    _salt: str = None

    def __init__(self):
        pass

    @property
    def etype(self) -> EncryptionTypes:
        return self._etype

    @etype.setter
    def etype(self, value) -> None:
        self._etype = value

    @property
    def salt(self) -> str:
        return self._salt

    @salt.setter
    def salt(self, value) -> None:
        self._salt = value

    @classmethod
    def load(cls, data: EtypeInfoEntryAsn1):
        if isinstance(data, bytes):
            data = EtypeInfoEntryAsn1.load(data)
        if isinstance(data, EtypeInfoEntry):
            data = data.to_asn1()
        tmp = cls()
        if ETYPE_INFO_ETYPE in data:
            if data[ETYPE_INFO_ETYPE].native is not None:
                tmp.etype = EncryptionTypes(data[ETYPE_INFO_ETYPE].native)
        if ETYPE_INFO_SALT in data:
            if data[ETYPE_INFO_SALT].native is not None:
                tmp.salt = data[ETYPE_INFO_SALT].native
        return tmp

    def to_asn1(self) -> EtypeInfoEntryAsn1:
        etype_info = EtypeInfoEntryAsn1()
        if self._etype is not None:
            etype_info[ETYPE_INFO_ETYPE] = self._etype.value
        if self._salt is not None:
            etype_info[ETYPE_INFO_SALT] = self._salt
        return etype_info

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()
