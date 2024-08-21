from ipapocket.krb5.types.int32 import Int32
from ipapocket.krb5.types.kerberos_time import KerberosTime
from ipapocket.krb5.asn1 import LastReqAsn1
from ipapocket.krb5.fields import LAST_REQ_LR_TYPE, LAST_REQ_LR_VALUE


class LastReq:
    _lr_type: Int32 = None
    _lr_value: KerberosTime = None

    def __init__(self):
        pass

    @property
    def lr_type(self) -> Int32:
        return self._lr_type

    @lr_type.setter
    def lr_type(self, value) -> None:
        self._lr_type = value

    @property
    def lr_value(self) -> KerberosTime:
        return self._lr_value

    @lr_value.setter
    def lr_value(self, value) -> None:
        self._lr_value = value

    @classmethod
    def load(cls, data: LastReqAsn1):
        if isinstance(data, LastReq):
            data = data.to_asn1()
        tmp = cls()
        if LAST_REQ_LR_TYPE in data:
            if data[LAST_REQ_LR_TYPE].native is not None:
                tmp.lr_type = Int32.load(data[LAST_REQ_LR_TYPE])
        if LAST_REQ_LR_VALUE in data:
            if data[LAST_REQ_LR_VALUE].native is not None:
                tmp.lr_value = KerberosTime.load(data[LAST_REQ_LR_VALUE])
        return tmp

    def to_asn1(self) -> LastReqAsn1:
        last_req = LastReqAsn1()
        if self._lr_type is not None:
            last_req[LAST_REQ_LR_TYPE] = self._lr_type.to_asn1()
        if self._lr_value is not None:
            last_req[LAST_REQ_LR_VALUE] = self._lr_value.to_asn1()
        return last_req

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()
