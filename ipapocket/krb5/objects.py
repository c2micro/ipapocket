import ipapocket.krb5.constants
import ipapocket.krb5.asn1 as asn1
from bitarray import bitarray


class PrincipalName:
    def __init__(self, type=None, value=None):
        self._type = type
        self._value = value

    def to_asn1(self):
        principal_name = asn1.PrincipalNameAsn1()
        if self._type is not None:
            principal_name["name-type"] = self._type
        if self._value is not None:
            principal_name["name-string"] = self._value
        return principal_name


class KdcOptions:
    def __init__(self):
        self._options = list()

    def add(self, option):
        self._options.append(option)

    def to_asn1(self):
        b_arr = bitarray(32)
        for option in self._options:
            b_arr[option.value] = 1
        return asn1.KdcOptionsAsn1(tuple(b_arr.tolist()))


class Realm:
    def __init__(self, realm=None):
        self._realm = realm

    def to_asn1(self):
        return asn1.RealmAsn1(self._realm)


class KerberosTime:
    def __init__(self, krb_time=None):
        self._krb_time = krb_time

    def to_asn1(self):
        return asn1.KerberosTimeAsn1(self._krb_time)


class Int32:
    def __init__(self, value=None):
        self._value = value

    def to_asn1(self):
        return asn1.Int32Asn1(self._value)


class UInt32:
    def __init__(self, value=None):
        self._value = value

    def to_asn1(self):
        return asn1.UInt32Asn1(self._value)


class EncTypes:
    def __init__(self, etypes=None):
        self._etypes = etypes

    def to_asn1(self):
        final = list()
        for t in self._etypes:
            final.append(t.value)
        return asn1.EncTypesAsn1(final)


class KdcReqBody:
    def __init__(self):
        self._kdc_options = None
        self._cname = None
        self._realm = None
        self._sname = None
        self._till = None
        self._rtime = None
        self._nonce = None
        self._etype = None

    def set_kdc_options(self, options):
        self._kdc_options = options

    def set_cname(self, cname):
        self._cname = cname

    def set_realm(self, realm):
        self._realm = realm

    def set_sname(self, sname):
        self._sname = sname

    def set_till(self, till):
        self._till = till

    def set_rtime(self, rtime):
        self._rtime = rtime

    def set_nonce(self, nonce):
        self._nonce = nonce

    def set_etypes(self, etypes):
        self._etype = etypes

    def to_asn1(self):
        kdc_req_body = asn1.KdcReqBodyAsn1()
        if self._kdc_options is not None:
            kdc_req_body["kdc-options"] = self._kdc_options.to_asn1()
        if self._cname is not None:
            kdc_req_body["cname"] = self._cname.to_asn1()
        if self._realm is not None:
            kdc_req_body["realm"] = self._realm.to_asn1()
        if self._sname is not None:
            kdc_req_body["sname"] = self._sname.to_asn1()
        if self._till is not None:
            kdc_req_body["till"] = self._till.to_asn1()
        if self._rtime is not None:
            kdc_req_body["rtime"] = self._rtime.to_asn1()
        if self._nonce is not None:
            kdc_req_body["nonce"] = self._nonce.to_asn1()
        if self._etype is not None:
            kdc_req_body["etype"] = self._etype.to_asn1()
        return kdc_req_body


class PaData:
    def __init__(self):
        self._padata = None

    def to_asn1(self):
        return asn1.PaDatasAsn1(
            {},
        )


class KdcReq:
    def __init__(self):
        self._pvno = None
        self._msg_type = None
        self._padata = None
        self._req_body = None

    def set_pvno(self, pvno):
        self._pvno = pvno

    def set_msg_type(self, msg_type):
        self._msg_type = msg_type

    def set_req_body(self, req_body):
        self._req_body = req_body

    def set_padata(self, padata):
        self._padata = padata

    def to_asn1(self):
        kdc_req = asn1.KdcReqAsn1()
        if self._pvno is not None:
            kdc_req["pvno"] = self._pvno.to_asn1()
        if self._msg_type is not None:
            kdc_req["msg-type"] = self._msg_type.to_asn1()
        if self._req_body is not None:
            kdc_req["req-body"] = self._req_body.to_asn1()
        if self._padata is not None:
            kdc_req["padata"] = self._padata.to_asn1()
        return kdc_req


class AsReq:
    def __init__(self, req):
        self._req = req

    def set_req(self, req):
        self._req = req

    def to_asn1(self):
        return asn1.AsReqAsn1(self._req.to_asn1().native)
