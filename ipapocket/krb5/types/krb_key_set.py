from ipapocket.krb5.types.uint16 import UInt16
from ipapocket.krb5.types.uint32 import UInt32
from ipapocket.krb5.types.krb_keys import KrbKeys
from ipapocket.krb5.asn1 import KrbKeySetAsn1
from ipapocket.krb5.fields import (
    KRB_KEY_SET_ATTRIBUTE_MAJOR_VNO,
    KRB_KEY_SET_ATTRIBUTE_MINOR_VNO,
    KRB_KEY_SET_KEYS,
    KRB_KEY_SET_KVNO,
    KRB_KEY_SET_MKVNO,
)


class KrbKeySet:
    _attribute_major_vno: UInt16 = None
    _attribute_minor_vno: UInt16 = None
    _kvno: UInt32 = None
    _mkvno: UInt32 = None
    _keys: KrbKeys = None

    @property
    def attribute_major_vno(self) -> UInt16:
        return self._attribute_major_vno

    @attribute_major_vno.setter
    def attribute_major_vno(self, value) -> None:
        self._attribute_major_vno = value

    @property
    def attribute_minor_vno(self) -> UInt16:
        return self._attribute_minor_vno

    @attribute_minor_vno.setter
    def attribute_minor_vno(self, value) -> None:
        self._attribute_minor_vno = value

    @property
    def kvno(self) -> UInt32:
        return self._kvno

    @kvno.setter
    def kvno(self, value) -> None:
        self._kvno = value

    @property
    def mkvno(self) -> UInt32:
        return self._mkvno

    @mkvno.setter
    def mkvno(self, value) -> None:
        self._mkvno = value

    @property
    def keys(self) -> KrbKeys:
        return self._keys

    @keys.setter
    def keys(self, value) -> None:
        self._keys = value

    @classmethod
    def load(cls, data: KrbKeySetAsn1):
        if isinstance(data, KrbKeySet):
            data = data.to_asn1()
        if isinstance(data, bytes):
            data = KrbKeySetAsn1.load(data)
        tmp = cls()
        if KRB_KEY_SET_ATTRIBUTE_MAJOR_VNO in data:
            if data[KRB_KEY_SET_ATTRIBUTE_MAJOR_VNO].native is not None:
                tmp.attribute_major_vno = UInt16.load(
                    data[KRB_KEY_SET_ATTRIBUTE_MAJOR_VNO]
                )
        if KRB_KEY_SET_ATTRIBUTE_MINOR_VNO in data:
            if data[KRB_KEY_SET_ATTRIBUTE_MINOR_VNO].native is not None:
                tmp.attribute_minor_vno = UInt16.load(
                    data[KRB_KEY_SET_ATTRIBUTE_MINOR_VNO]
                )
        if KRB_KEY_SET_KVNO in data:
            if data[KRB_KEY_SET_KVNO].native is not None:
                tmp.kvno = UInt32.load(data[KRB_KEY_SET_KVNO])
        if KRB_KEY_SET_MKVNO in data:
            if data[KRB_KEY_SET_MKVNO].native is not None:
                tmp.mkvno = UInt32.load(data[KRB_KEY_SET_MKVNO])
        if KRB_KEY_SET_KEYS in data:
            if data[KRB_KEY_SET_KEYS].native is not None:
                tmp.keys = KrbKeys.load(data[KRB_KEY_SET_KEYS])
        return tmp

    def to_asn1(self) -> KrbKeySetAsn1:
        krb_key_set = KrbKeySetAsn1()
        if self.attribute_major_vno is not None:
            krb_key_set[KRB_KEY_SET_ATTRIBUTE_MAJOR_VNO] = (
                self.attribute_major_vno.to_asn1()
            )
        if self.attribute_minor_vno is not None:
            krb_key_set[KRB_KEY_SET_ATTRIBUTE_MINOR_VNO] = (
                self.attribute_minor_vno.to_asn1()
            )
        if self.kvno is not None:
            krb_key_set[KRB_KEY_SET_KVNO] = self.kvno.to_asn1()
        if self.mkvno is not None:
            krb_key_set[KRB_KEY_SET_MKVNO] = self.mkvno.to_asn1()
        if self.keys is not None:
            krb_key_set[KRB_KEY_SET_KEYS] = self.keys.to_asn1()
        return KrbKeySetAsn1()
