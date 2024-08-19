from ipapocket.krb5.types.kdc_req import KdcReq
from ipapocket.krb5.asn1 import AsReqAsn1
from ipapocket.exceptions.krb5 import InvalidAsReqRequest
from ipapocket.krb5.fields import AS_REQ


class AsReq:
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
            raise InvalidAsReqRequest()

    @classmethod
    def load(cls, data: AsReqAsn1):
        if isinstance(data, AsReq):
            data = data.to_asn1()
        return cls(KdcReq.load(data))

    def to_asn1(self):
        return AsReqAsn1(self._req.to_asn1().native)

    def pretty(self):
        """
        Convert object to dict
        """
        if self.req is not None:
            value = self.req.pretty()
        else:
            value = None
        return {AS_REQ: value}

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()
