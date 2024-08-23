from ipapocket.krb5.types.int32 import Int32
from ipapocket.krb5.types.method_data import MethodData
from ipapocket.krb5.types.realm import Realm
from ipapocket.krb5.types.principal_name import PrincipalName
from ipapocket.krb5.types.ticket import Ticket
from ipapocket.krb5.types.encrypted_data import EncryptedData
from ipapocket.krb5.types.kerberos_string import KerberosString
from ipapocket.krb5.constants import MessageType
from ipapocket.krb5.asn1 import KdcRepAsn1
from ipapocket.krb5.constants.fields import (
    KDC_REP_CNAME,
    KDC_REP_CREALM,
    KDC_REP_ENC_PART,
    KDC_REP_MSG_TYPE,
    KDC_REP_PADATA,
    KDC_REP_PVNO,
    KDC_REP_TICKET,
)


class KdcRep:
    _pvno: Int32 = None
    _msg_type: MessageType = None
    _pdata: MethodData = None
    _crealm: Realm = None
    _cname: PrincipalName = None
    _ticket: Ticket = None
    _enc_part: EncryptedData = None

    def __init__(self):
        pass

    @property
    def pvno(self) -> Int32:
        return self._pvno

    @pvno.setter
    def pvno(self, value) -> None:
        self._pvno = value

    @property
    def msg_type(self) -> MessageType:
        return self._msg_type

    @msg_type.setter
    def msg_type(self, value) -> None:
        self._msg_type = value

    @property
    def padata(self) -> MethodData:
        return self._pdata

    @padata.setter
    def padata(self, value) -> None:
        self._pdata = value

    @property
    def crealm(self) -> Realm:
        return self._crealm

    @crealm.setter
    def crealm(self, value) -> None:
        if isinstance(value, KerberosString | str):
            self._crealm = Realm(value)
        elif isinstance(value, Realm):
            self._crealm = value
        else:
            raise

    @property
    def cname(self) -> PrincipalName:
        return self._cname

    @cname.setter
    def cname(self, value) -> None:
        self._cname = value

    @property
    def ticket(self) -> Ticket:
        return self._ticket

    @ticket.setter
    def ticket(self, value) -> None:
        self._ticket = value

    @property
    def enc_part(self) -> EncryptedData:
        return self._enc_part

    @enc_part.setter
    def enc_part(self, value) -> None:
        self._enc_part = value

    @classmethod
    def load(cls, data):
        if isinstance(data, KdcRep):
            data = data.to_asn1()
        tmp = cls()
        if KDC_REP_PVNO in data:
            if data[KDC_REP_PVNO].native is not None:
                tmp.pvno = Int32.load(data[KDC_REP_PVNO])
        if KDC_REP_MSG_TYPE in data:
            if data[KDC_REP_MSG_TYPE].native is not None:
                tmp.msg_type = MessageType(data[KDC_REP_MSG_TYPE].native)
        if KDC_REP_PADATA in data:
            if data[KDC_REP_PADATA].native is not None:
                tmp.padata = MethodData.load(data[KDC_REP_PADATA])
        if KDC_REP_CREALM in data:
            if data[KDC_REP_CREALM].native is not None:
                tmp.crealm = Realm.load(data[KDC_REP_CREALM])
        if KDC_REP_CNAME in data:
            if data[KDC_REP_CNAME].native is not None:
                tmp.cname = PrincipalName.load(data[KDC_REP_CNAME])
        if KDC_REP_TICKET in data:
            if data[KDC_REP_TICKET].native is not None:
                tmp.ticket = Ticket.load(data[KDC_REP_TICKET])
        if KDC_REP_ENC_PART in data:
            if data[KDC_REP_ENC_PART].native is not None:
                tmp.enc_part = EncryptedData.load(data[KDC_REP_ENC_PART])
        return tmp

    def to_asn1(self) -> KdcRepAsn1:
        return KdcRepAsn1()

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()
