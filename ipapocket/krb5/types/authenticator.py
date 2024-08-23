from ipapocket.krb5.types.int32 import Int32
from ipapocket.krb5.types.realm import Realm
from ipapocket.krb5.types.principal_name import PrincipalName
from ipapocket.krb5.types.checksum import Checksum
from ipapocket.krb5.types.microseconds import Microseconds
from ipapocket.krb5.types.kerberos_time import KerberosTime
from ipapocket.krb5.types.encryption_key import EncryptionKey
from ipapocket.krb5.types.uint32 import UInt32
from ipapocket.krb5.types.authorization_data import AuthorizationData
from ipapocket.krb5.constants.fields import (
    AUTHENTICATOR_AUTHENTICATOR_VNO,
    AUTHENTICATOR_AUTHORIZATION_DATA,
    AUTHENTICATOR_CKSUM,
    AUTHENTICATOR_CNAME,
    AUTHENTICATOR_CREALM,
    AUTHENTICATOR_CTIME,
    AUTHENTICATOR_CUSEC,
    AUTHENTICATOR_SEQ_NUMBER,
    AUTHENTICATOR_SUBKEY,
)
from ipapocket.krb5.asn1 import AuthenticatorAsn1


class Authenticator:
    _authenticator_vno: Int32 = None
    _crealm: Realm = None
    _cname: PrincipalName = None
    _cksum: Checksum = None
    _cusec: Microseconds = None
    _ctime: KerberosTime = None
    _subkey: EncryptionKey = None
    _seq_number: UInt32 = None
    _authorization_data: AuthorizationData = None

    @property
    def authenticator_vno(self) -> Int32:
        return self._authenticator_vno

    @authenticator_vno.setter
    def authenticator_vno(self, value) -> None:
        if isinstance(value, int):
            self._authenticator_vno = Int32.load(value)
        else:
            self._authenticator_vno = value

    @property
    def crealm(self) -> Realm:
        return self._crealm

    @crealm.setter
    def crealm(self, value) -> None:
        self._crealm = value

    @property
    def cname(self) -> PrincipalName:
        return self._cname

    @cname.setter
    def cname(self, value) -> None:
        self._cname = value

    @property
    def cksum(self) -> Checksum:
        return self._cksum

    @cksum.setter
    def cksum(self, value) -> None:
        self._cksum = value

    @property
    def cusec(self) -> Microseconds:
        return self._cusec

    @cusec.setter
    def cusec(self, value) -> None:
        self._cusec = value

    @property
    def ctime(self) -> KerberosTime:
        return self._ctime

    @ctime.setter
    def ctime(self, value) -> None:
        self._ctime = value

    @property
    def subkey(self) -> EncryptionKey:
        return self._subkey

    @subkey.setter
    def subkey(self, value) -> None:
        self._subkey = value

    @property
    def seq_number(self) -> UInt32:
        return self._seq_number

    @seq_number.setter
    def seq_number(self, value) -> None:
        if isinstance(value, int):
            self._seq_number = UInt32.load(value)
        else:
            self._seq_number = value

    @property
    def authorization_data(self) -> AuthorizationData:
        return self._authorization_data

    @authorization_data.setter
    def authorization_data(self, value) -> None:
        self._authorization_data = value

    @classmethod
    def load(cls, data: AuthenticatorAsn1):
        if isinstance(data, Authenticator):
            data = data.to_asn1()
        tmp = cls()
        if AUTHENTICATOR_AUTHENTICATOR_VNO in data:
            if data[AUTHENTICATOR_AUTHENTICATOR_VNO].native is not None:
                tmp.authenticator_vno = Int32.load(
                    data[AUTHENTICATOR_AUTHENTICATOR_VNO]
                )
        if AUTHENTICATOR_CREALM in data:
            if data[AUTHENTICATOR_CREALM].native is not None:
                tmp.crealm = Realm.load(data[AUTHENTICATOR_CREALM])
        if AUTHENTICATOR_CNAME in data:
            if data[AUTHENTICATOR_CNAME].native is not None:
                tmp.cname = PrincipalName.load(data[AUTHENTICATOR_CNAME])
        if AUTHENTICATOR_CKSUM in data:
            if data[AUTHENTICATOR_CKSUM].native is not None:
                tmp.cksum = Checksum.load(data[AUTHENTICATOR_CKSUM])
        if AUTHENTICATOR_CUSEC in data:
            if data[AUTHENTICATOR_CUSEC].native is not None:
                tmp.cusec = Microseconds.load(data[AUTHENTICATOR_CUSEC])
        if AUTHENTICATOR_CTIME in data:
            if data[AUTHENTICATOR_CTIME].native is not None:
                tmp.ctime = KerberosTime.load(data[AUTHENTICATOR_CTIME])
        if AUTHENTICATOR_SUBKEY in data:
            if data[AUTHENTICATOR_SUBKEY].native is not None:
                tmp.subkey = EncryptionKey.load(data[AUTHENTICATOR_SUBKEY])
        if AUTHENTICATOR_SEQ_NUMBER in data:
            if data[AUTHENTICATOR_SEQ_NUMBER].native is not None:
                tmp.seq_number = UInt32.load(data[AUTHENTICATOR_SEQ_NUMBER])
        if AUTHENTICATOR_AUTHORIZATION_DATA in data:
            if data[AUTHENTICATOR_AUTHORIZATION_DATA].native is not None:
                tmp.authorization_data = AuthorizationData.load(
                    data[AUTHENTICATOR_AUTHORIZATION_DATA]
                )
        return tmp

    def to_asn1(self) -> AuthenticatorAsn1:
        authenticator = AuthenticatorAsn1()
        if self.authenticator_vno is not None:
            authenticator[AUTHENTICATOR_AUTHENTICATOR_VNO] = (
                self.authenticator_vno.to_asn1()
            )
        if self.crealm is not None:
            authenticator[AUTHENTICATOR_CREALM] = self.crealm.to_asn1()
        if self.cname is not None:
            authenticator[AUTHENTICATOR_CNAME] = self.cname.to_asn1()
        if self.cksum is not None:
            authenticator[AUTHENTICATOR_CKSUM] = self.cksum.to_asn1()
        if self.cusec is not None:
            authenticator[AUTHENTICATOR_CUSEC] = self.cusec.to_asn1()
        if self.ctime is not None:
            authenticator[AUTHENTICATOR_CTIME] = self.ctime.to_asn1()
        if self.subkey is not None:
            authenticator[AUTHENTICATOR_SUBKEY] = self.subkey.to_asn1()
        if self.seq_number is not None:
            authenticator[AUTHENTICATOR_SEQ_NUMBER] = self.seq_number.to_asn1()
        if self.authorization_data is not None:
            authenticator[AUTHENTICATOR_AUTHORIZATION_DATA] = (
                self.authorization_data.to_asn1()
            )
        return authenticator

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()
