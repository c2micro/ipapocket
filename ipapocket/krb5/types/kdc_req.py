from ipapocket.krb5.types.int32 import Int32
from ipapocket.krb5.constants import MessageTypes
from ipapocket.krb5.types.method_data import MethodData
from ipapocket.krb5.types.kdc_req_body import KdcReqBody
from ipapocket.exceptions.krb5 import InvalidTypeInKdcReq, InvalidEncTypesValueType
from ipapocket.krb5.fields import (
    KDC_REQ,
    KDC_REQ_PVNO,
    KDC_REQ_MSG_TYPE,
    KDC_REQ_PADATA,
    KDC_REQ_REQ_BODY,
)
from ipapocket.krb5.asn1 import KdcReqAsn1


class KdcReq:
    _pvno: Int32 = None
    _msg_type: MessageTypes = None
    _padata: MethodData = None
    _req_body: KdcReqBody = None

    def __init__(self):
        pass

    @property
    def pvno(self) -> Int32:
        return self._pvno

    @pvno.setter
    def pvno(self, value) -> None:
        if isinstance(value, int):
            self._pvno = Int32(value)
        elif isinstance(value, Int32):
            self._pvno = value
        else:
            raise InvalidTypeInKdcReq(KDC_REQ_PVNO, value)

    @property
    def msg_type(self) -> Int32:
        return self._msg_type

    @msg_type.setter
    def msg_type(self, value) -> None:
        if isinstance(value, MessageTypes):
            self._msg_type = value
        elif isinstance(value, int):
            self._msg_type = MessageTypes(value)
        else:
            raise InvalidTypeInKdcReq(KDC_REQ_MSG_TYPE, value)

    @property
    def padata(self) -> MethodData:
        return self._padata

    @padata.setter
    def padata(self, value) -> None:
        if not isinstance(value, MethodData):
            raise InvalidTypeInKdcReq(KDC_REQ_PADATA, value)
        self._padata = value

    @property
    def req_body(self) -> KdcReqBody:
        return self._req_body

    @req_body.setter
    def req_body(self, value) -> None:
        if not isinstance(value, KdcReqBody):
            raise InvalidEncTypesValueType(KDC_REQ_REQ_BODY, value)
        self._req_body = value

    @classmethod
    def load(cls, data: KdcReqAsn1):
        if isinstance(data, KdcReq):
            data = data.to_asn1()
        tmp = cls()
        if KDC_REQ_PVNO in data:
            if data[KDC_REQ_PVNO].native is not None:
                tmp.pvno = Int32.load(data[KDC_REQ_PVNO])
        if KDC_REQ_MSG_TYPE in data:
            if data[KDC_REQ_MSG_TYPE].native is not None:
                tmp.msg_type = MessageTypes(data[KDC_REQ_MSG_TYPE].native)
        if KDC_REQ_PADATA in data:
            if data[KDC_REQ_PADATA].native is not None:
                tmp.padata = MethodData.load(data[KDC_REQ_PADATA])
        if KDC_REQ_REQ_BODY in data:
            if data[KDC_REQ_REQ_BODY].native is not None:
                tmp.req_body = KdcReqBody.load(data[KDC_REQ_REQ_BODY])
        return tmp

    def to_asn1(self):
        kdc_req = KdcReqAsn1()
        if self._pvno is not None:
            kdc_req[KDC_REQ_PVNO] = self._pvno.to_asn1()
        if self._msg_type is not None:
            kdc_req[KDC_REQ_MSG_TYPE] = self._msg_type.value
        if self._req_body is not None:
            kdc_req[KDC_REQ_REQ_BODY] = self._req_body.to_asn1()
        if self._padata is not None:
            kdc_req[KDC_REQ_PADATA] = self._padata.to_asn1()
        return kdc_req

    def pretty(self):
        """
        Convert object to dict
        """
        tmp = dict()
        if self.pvno is not None:
            tmp[KDC_REQ_PVNO] = self.pvno.pretty()
        else:
            tmp[KDC_REQ_PVNO] = None
        if self.msg_type is not None:
            tmp[KDC_REQ_MSG_TYPE] = self.msg_type.name
        else:
            tmp[KDC_REQ_MSG_TYPE] = None
        if self.req_body is not None:
            tmp[KDC_REQ_REQ_BODY] = self.req_body.pretty()
        else:
            tmp[KDC_REQ_REQ_BODY] = None
        if self.padata is not None:
            tmp[KDC_REQ_PADATA] = self.padata.pretty()
        else:
            tmp[KDC_REQ_PADATA] = None
        return {KDC_REQ: tmp}

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()
