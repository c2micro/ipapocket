from ipapocket.krb5.types.last_req import LastReq
from ipapocket.krb5.asn1 import LastReqsAsn1


class LastReqs:
    _reqs: list[LastReq] = None

    def __init__(self):
        self._reqs = list()

    def add(self, value: LastReq):
        self._reqs.append(value)

    def clear(self):
        self._reqs = list()

    @classmethod
    def load(cls, data: LastReqsAsn1):
        if isinstance(data, LastReqs):
            data = data.to_asn1()
        tmp = cls()
        for v in data:
            tmp.add(LastReq.load(v))
        return tmp

    def to_asn1(self) -> LastReqsAsn1:
        tmp = list()
        for v in self._reqs:
            tmp.append(v.to_asn1())
        return LastReqsAsn1(tmp)

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()
