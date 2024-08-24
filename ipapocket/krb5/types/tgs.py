from ipapocket.krb5.types.kdc_rep import KdcRep
from ipapocket.krb5.crypto.backend import Key
from ipapocket.krb5.types.enc_kdc_rep_part import EncKdcRepPart


# special class wrapper to store prepared structures for further processing
class Tgs:
    _kdc_rep: KdcRep = None
    _epart: EncKdcRepPart = None
    _session_key: Key = None

    @property
    def kdc_rep(self) -> KdcRep:
        return self._kdc_rep

    @kdc_rep.setter
    def kdc_rep(self, value) -> None:
        self._kdc_rep = value

    @property
    def epart(self) -> EncKdcRepPart:
        return self._epart

    @epart.setter
    def epart(self, value) -> None:
        self._epart = value

    @property
    def session_key(self) -> Key:
        return self._session_key

    @session_key.setter
    def session_key(self, value) -> None:
        self._session_key = value
