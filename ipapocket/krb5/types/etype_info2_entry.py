from ipapocket.krb5.constants import EncryptionType
from ipapocket.krb5.types.kerberos_string import KerberosString
from ipapocket.krb5.asn1 import EtypeInfo2EntryAsn1
from ipapocket.krb5.constants.fields import (
    ETYPE_INFO2_ETYPE,
    ETYPE_INFO2_S2KPARAMS,
    ETYPE_INFO2_SALT,
)


class EtypeInfo2Entry:
    _etype: EncryptionType = None
    _salt: KerberosString = None
    _s2kparams: str = None

    def __init__(self):
        pass

    @property
    def etype(self) -> EncryptionType:
        return self._etype

    @etype.setter
    def etype(self, value) -> None:
        self._etype = value

    @property
    def salt(self) -> KerberosString:
        return self._salt

    @salt.setter
    def salt(self, value) -> None:
        self._salt = value

    @property
    def s2kparams(self) -> str:
        return self._s2kparams

    @s2kparams.setter
    def s2kparams(self, value) -> None:
        self._s2kparams = value

    @classmethod
    def load(cls, data: EtypeInfo2EntryAsn1):
        if isinstance(data, bytes):
            data = EtypeInfo2EntryAsn1.load(data)
        if isinstance(data, EtypeInfo2Entry):
            data = data.to_asn1()
        tmp = cls()
        if ETYPE_INFO2_ETYPE in data:
            if data[ETYPE_INFO2_ETYPE].native is not None:
                tmp.etype = EncryptionType(data[ETYPE_INFO2_ETYPE].native)
        if ETYPE_INFO2_SALT in data:
            if data[ETYPE_INFO2_SALT].native is not None:
                tmp.salt = KerberosString.load(data[ETYPE_INFO2_SALT])
        if ETYPE_INFO2_S2KPARAMS in data:
            if data[ETYPE_INFO2_S2KPARAMS] is not None:
                tmp.s2kparams = data[ETYPE_INFO2_S2KPARAMS].native
        return tmp

    def to_asn1(self) -> EtypeInfo2EntryAsn1:
        etype_info2_entry = EtypeInfo2EntryAsn1()
        if self._etype is not None:
            etype_info2_entry[ETYPE_INFO2_ETYPE] = self._etype.value
        if self._salt is not None:
            etype_info2_entry[ETYPE_INFO2_SALT] = self._salt.to_asn1()
        if self._s2kparams is not None:
            etype_info2_entry[ETYPE_INFO2_S2KPARAMS] = self._s2kparams
        return etype_info2_entry

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()
