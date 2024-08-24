from ipapocket.krb5.types.kdc_options import KdcOptions
from ipapocket.krb5.types.principal_name import PrincipalName
from ipapocket.krb5.types.realm import Realm
from ipapocket.krb5.types.kerberos_time import KerberosTime
from ipapocket.krb5.types.uint32 import UInt32
from ipapocket.krb5.types.enc_types import EncTypes
from ipapocket.krb5.types.host_addresses import HostAddresses
from ipapocket.krb5.types.encrypted_data import EncryptedData
from ipapocket.krb5.types.tickets import Tickets
from ipapocket.exceptions.krb5 import InvalidTypeInKdcReqBody
from ipapocket.krb5.constants.fields import (
    KDC_REQ_BODY_ETYPE,
    KDC_REQ_BODY_ADDITIONAL_TICKETS,
    KDC_REQ_BODY_ADDRESSES,
    KDC_REQ_BODY_CNAME,
    KDC_REQ_BODY_FROM,
    KDC_REQ_BODY_NONCE,
    KDC_REQ_BODY_ENC_AUTH_DATA,
    KDC_REQ_BODY_KDC_OPTIONS,
    KDC_REQ_BODY_REALM,
    KDC_REQ_BODY_RTIME,
    KDC_REQ_BODY_SNAME,
    KDC_REQ_BODY_TILL,
    KDC_REQ_BODY,
)
from ipapocket.krb5.asn1 import KdcReqBodyAsn1


class KdcReqBody:
    _kdc_options: KdcOptions = None
    _cname: PrincipalName = None
    _realm: Realm = None
    _sname: PrincipalName = None
    _from: KerberosTime = None
    _till: KerberosTime = None
    _rtime: KerberosTime = None
    _nonce: UInt32 = None
    _etype: EncTypes = None
    _addresses: HostAddresses = None
    _enc_authorization_data: EncryptedData = None
    _additional_tickets: Tickets = None

    def __init__(self):
        pass

    @property
    def kdc_options(self):
        return self._kdc_options

    @kdc_options.setter
    def kdc_options(self, value):
        if not isinstance(value, KdcOptions):
            raise InvalidTypeInKdcReqBody("kdc_options", value)
        self._kdc_options = value

    @property
    def cname(self):
        return self._cname

    @cname.setter
    def cname(self, value):
        if not isinstance(value, PrincipalName):
            raise InvalidTypeInKdcReqBody("cname", value)
        self._cname = value

    @property
    def realm(self) -> Realm:
        return self._realm

    @realm.setter
    def realm(self, value):
        if isinstance(value, str):
            self._realm = Realm(value)
        elif isinstance(value, Realm):
            self._realm = value
        else:
            raise InvalidTypeInKdcReqBody("realm", value)

    @property
    def sname(self) -> PrincipalName:
        return self._sname

    @sname.setter
    def sname(self, value) -> None:
        if not isinstance(value, PrincipalName):
            raise InvalidTypeInKdcReqBody("sname", value)
        self._sname = value

    @property
    def from_k(self) -> KerberosTime:
        return self._from

    @from_k.setter
    def from_k(self, value) -> None:
        if not isinstance(value, KerberosTime):
            raise InvalidTypeInKdcReqBody("from", value)
        self._from = value

    @property
    def till(self) -> KerberosTime:
        return self._till

    @till.setter
    def till(self, value) -> None:
        if not isinstance(value, KerberosTime):
            raise InvalidTypeInKdcReqBody("till", value)
        self._till = value

    @property
    def rtime(self) -> KerberosTime:
        return self._rtime

    @rtime.setter
    def rtime(self, value) -> None:
        if value is None:
            self._rtime = None
        elif not isinstance(value, KerberosTime):
            raise InvalidTypeInKdcReqBody("rtime", value)
        self._rtime = value

    @property
    def nonce(self) -> UInt32:
        return self._nonce

    @nonce.setter
    def nonce(self, value) -> None:
        if not isinstance(value, UInt32):
            raise InvalidTypeInKdcReqBody("nonce", value)
        self._nonce = value

    @property
    def etype(self) -> EncTypes:
        return self._etype

    @etype.setter
    def etype(self, value) -> None:
        if not isinstance(value, EncTypes):
            raise InvalidTypeInKdcReqBody("etype", value)
        self._etype = value

    @property
    def addresses(self) -> HostAddresses:
        return self._addresses

    @addresses.setter
    def addresses(self, value) -> None:
        if not isinstance(value, HostAddresses):
            raise InvalidTypeInKdcReqBody("addresses", value)
        self._addresses = value

    @property
    def enc_authorization_data(self) -> EncryptedData:
        return self._enc_authorization_data

    @enc_authorization_data.setter
    def enc_authorization_data(self, value) -> None:
        if not isinstance(value, EncryptedData):
            raise InvalidTypeInKdcReqBody("enc_authorization_data", value)
        self._enc_authorization_data = value

    @property
    def additional_tickets(self) -> Tickets:
        return self._additional_tickets

    @additional_tickets.setter
    def additional_tickets(self, value) -> None:
        if not isinstance(value, Tickets):
            raise InvalidTypeInKdcReqBody("additional_tickets", value)
        self._additional_tickets = value

    @classmethod
    def load(cls, data: KdcReqBodyAsn1):
        if isinstance(data, KdcReqBody):
            data = data.to_asn1()
        tmp = cls()
        if KDC_REQ_BODY_KDC_OPTIONS in data:
            if data[KDC_REQ_BODY_KDC_OPTIONS].native is not None:
                tmp.kdc_options = KdcOptions.load(data[KDC_REQ_BODY_KDC_OPTIONS])
        if KDC_REQ_BODY_CNAME in data:
            if data[KDC_REQ_BODY_CNAME].native is not None:
                tmp.cname = PrincipalName.load(data[KDC_REQ_BODY_CNAME])
        if KDC_REQ_BODY_REALM in data:
            if data[KDC_REQ_BODY_REALM].native is not None:
                tmp.realm = Realm.load(data[KDC_REQ_BODY_REALM])
        if KDC_REQ_BODY_SNAME in data:
            if data[KDC_REQ_BODY_SNAME].native is not None:
                tmp.sname = PrincipalName.load(data[KDC_REQ_BODY_SNAME])
        if KDC_REQ_BODY_FROM in data:
            if data[KDC_REQ_BODY_FROM].native is not None:
                tmp.from_k = KerberosTime.load(data[KDC_REQ_BODY_FROM])
        if KDC_REQ_BODY_TILL in data:
            if data[KDC_REQ_BODY_TILL].native is not None:
                tmp.till = KerberosTime.load(data[KDC_REQ_BODY_TILL])
        if KDC_REQ_BODY_RTIME in data:
            if data[KDC_REQ_BODY_RTIME].native is not None:
                tmp.rtime = KerberosTime.load(data[KDC_REQ_BODY_RTIME])
        if KDC_REQ_BODY_NONCE in data:
            if data[KDC_REQ_BODY_NONCE].native is not None:
                tmp.nonce = UInt32.load(data[KDC_REQ_BODY_NONCE])
        if KDC_REQ_BODY_ETYPE in data:
            if data[KDC_REQ_BODY_ETYPE].native is not None:
                tmp.etype = EncTypes.load(data[KDC_REQ_BODY_ETYPE])
        if KDC_REQ_BODY_ADDRESSES in data:
            if data[KDC_REQ_BODY_ADDRESSES].native is not None:
                tmp.addresses = HostAddresses.load(data[KDC_REQ_BODY_ADDRESSES])
        if KDC_REQ_BODY_ENC_AUTH_DATA in data:
            if data[KDC_REQ_BODY_ENC_AUTH_DATA].native is not None:
                tmp.enc_authorization_data = EncryptedData.load(
                    data[KDC_REQ_BODY_ENC_AUTH_DATA]
                )
        if KDC_REQ_BODY_ADDITIONAL_TICKETS in data:
            if data[KDC_REQ_BODY_ADDITIONAL_TICKETS].native is not None:
                tmp.additional_tickets = Tickets.load(
                    data[KDC_REQ_BODY_ADDITIONAL_TICKETS]
                )
        return tmp

    def to_asn1(self):
        kdc_req_body = KdcReqBodyAsn1()
        if self._kdc_options is not None:
            kdc_req_body[KDC_REQ_BODY_KDC_OPTIONS] = self._kdc_options.to_asn1()
        if self._cname is not None:
            kdc_req_body[KDC_REQ_BODY_CNAME] = self._cname.to_asn1()
        if self._realm is not None:
            kdc_req_body[KDC_REQ_BODY_REALM] = self._realm.to_asn1()
        if self._sname is not None:
            kdc_req_body[KDC_REQ_BODY_SNAME] = self._sname.to_asn1()
        if self._from is not None:
            kdc_req_body[KDC_REQ_BODY_FROM] = self._from.to_asn1()
        if self._till is not None:
            kdc_req_body[KDC_REQ_BODY_TILL] = self._till.to_asn1()
        if self._rtime is not None:
            kdc_req_body[KDC_REQ_BODY_RTIME] = self._rtime.to_asn1()
        if self._nonce is not None:
            kdc_req_body[KDC_REQ_BODY_NONCE] = self._nonce.to_asn1()
        if self._etype is not None:
            kdc_req_body[KDC_REQ_BODY_ETYPE] = self._etype.to_asn1()
        if self._addresses is not None:
            kdc_req_body[KDC_REQ_BODY_ADDRESSES] = self._addresses.to_asn1()
        if self._enc_authorization_data is not None:
            kdc_req_body[KDC_REQ_BODY_ENC_AUTH_DATA] = (
                self._enc_authorization_data.to_asn1()
            )
        if self._additional_tickets is not None:
            kdc_req_body[KDC_REQ_BODY_ADDITIONAL_TICKETS] = (
                self._additional_tickets.to_asn1()
            )
        return kdc_req_body

    def pretty(self):
        """
        Convert object to dict
        """
        tmp = dict()
        # TODO
        return {KDC_REQ_BODY: tmp}

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()
