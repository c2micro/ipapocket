from ipapocket.krb5.types.uint32 import UInt32
from ipapocket.krb5.types.master_key import MasterKey
from ipapocket.krb5.asn1 import KrbMKeyAsn1
from ipapocket.krb5.constants.fields import KRB_MKEY_KEY, KRB_MKEY_KVNO


class KrbMKey:
    _kvno: UInt32 = None
    _key: MasterKey = None

    @property
    def kvno(self) -> UInt32:
        return self._kvno

    @kvno.setter
    def kvno(self, value) -> None:
        self._kvno = value

    @property
    def key(self) -> MasterKey:
        return self._key

    @key.setter
    def key(self, value) -> None:
        self._key = value

    @classmethod
    def load(cls, data: KrbMKeyAsn1):
        if isinstance(data, KrbMKey):
            data = data.to_asn1()
        if isinstance(data, bytes):
            data = KrbMKeyAsn1.load(data)
        tmp = cls()
        if KRB_MKEY_KVNO in data:
            if data[KRB_MKEY_KVNO].native is not None:
                tmp.kvno = UInt32.load(data[KRB_MKEY_KVNO])
        if KRB_MKEY_KEY in data:
            if data[KRB_MKEY_KEY].native is not None:
                tmp.key = MasterKey.load(data[KRB_MKEY_KEY])
        return tmp

    def to_asn1(self) -> KrbMKeyAsn1:
        krb_mkey = KrbMKeyAsn1()
        if self.kvno is not None:
            krb_mkey[KRB_MKEY_KVNO] = self.kvno.to_asn1()
        if self.key is not None:
            krb_mkey[KRB_MKEY_KEY] = self.key.to_asn1()
        return krb_mkey
