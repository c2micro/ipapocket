from ipapocket.krb5.types.krb_error import KrbError
from ipapocket.krb5.types.as_rep import AsRep
from ipapocket.krb5.types.tgs_rep import TgsRep
from ipapocket.krb5.asn1 import (
    KerberosResponseAsn1,
    KrbErrorAsn1,
    AsRepAsn1,
    TgsRepAsn1,
)
from ipapocket.krb5.constants.fields import (
    KERBEROS_RESPONSE_AS_REP,
    KERBEROS_RESPONSE_KRB_ERROR,
    KERBEROS_RESPONSE_TGS_REP,
)
from ipapocket.exceptions.krb5 import UnexpectedResponseType


class KerberosResponse:
    _krb_error: KrbError = None
    _as_rep: AsRep = None
    _tgs_rep: TgsRep = None

    def __init__(self):
        pass

    def is_krb_error(self) -> bool:
        return self._krb_error is not None

    def is_as_rep(self) -> bool:
        return self._as_rep is not None

    def is_tgs_rep(self) -> bool:
        return self._tgs_rep is not None

    @property
    def krb_error(self) -> KrbError:
        return self._krb_error

    @krb_error.setter
    def krb_error(self, value) -> None:
        self._krb_error = value

    @property
    def as_rep(self) -> AsRep:
        return self._as_rep

    @as_rep.setter
    def as_rep(self, value) -> None:
        self._as_rep = value

    @property
    def tgs_rep(self) -> TgsRep:
        return self._tgs_rep

    @tgs_rep.setter
    def tgs_rep(self, value) -> None:
        self._tgs_rep = value

    @classmethod
    def load(cls, data: KerberosResponseAsn1):
        if isinstance(data, bytes):
            data = KerberosResponseAsn1.load(data)
        tmp = cls()
        if data.name == KERBEROS_RESPONSE_KRB_ERROR:
            tmp.krb_error = KrbError.load(data.chosen)
            return tmp
        elif data.name == KERBEROS_RESPONSE_AS_REP:
            tmp.as_rep = AsRep.load(data.chosen)
            return tmp
        elif data.name == KERBEROS_RESPONSE_TGS_REP:
            tmp.tgs_rep = TgsRep.load(data.chosen)
            return tmp
        else:
            # unexpected response type
            raise UnexpectedResponseType(data.name)
