from ipapocket.krb5.types.kdc_req import KdcReq
from ipapocket.krb5.asn1 import TgsReqAsn1
from ipapocket.exceptions.krb5 import InvalidTgsReqRequest


class TgsReq:
    _req: KdcReq = None

    def __init__(self, req=None):
        self._req = self._validate_req(req)

    @property
    def req(self) -> KdcReq:
        return self._req

    @req.setter
    def req(self, value) -> None:
        self._req = self._validate_req(value)

    def _validate_req(self, req):
        if isinstance(req, KdcReq):
            return req
        else:
            raise InvalidTgsReqRequest()

    @classmethod
    def load(cls, data: TgsReqAsn1):
        if isinstance(data, TgsReq):
            data = data.to_asn1()
        return cls(KdcReq.load(data))

    def to_asn1(self):
        return TgsReqAsn1(self._req.to_asn1().native)

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()
