from ipapocket.krb5.objects import *
from asn1crypto import core


class OctetString:
    _length: int = None  # uint32_t
    _data: bytes = None  # uint8_t[uint32_t]

    def __init__(self, value=None):
        if value is None:
            value = b""
        self.data = value

    @property
    def length(self) -> int:
        return self._length

    @length.setter
    def length(self, value) -> None:
        self._length = value

    @property
    def data(self) -> bytes:
        return self._data

    @data.setter
    def data(self, value) -> None:
        if isinstance(value, str):
            value = value.encode()
        self._data = value
        self._length = len(self._data)

    def to_bytes(self) -> bytes:
        b = self._length.to_bytes(4, byteorder="big", signed=True)
        b += self._data
        return b


class Header:
    _tag: int = None  # uint16_t
    _taglen: int = None  # uint16_t
    _tagdata: bytes = None  # uint8_t[uint16_t]

    @property
    def tag(self) -> int:
        return self._tag

    @tag.setter
    def tag(self, value) -> None:
        self._tag = value

    @property
    def taglen(self) -> int:
        return self._taglen

    @taglen.setter
    def taglen(self, value) -> None:
        self._taglen = value

    @property
    def tagdata(self) -> bytes:
        return self._tagdata

    @tagdata.setter
    def tagdata(self, value) -> None:
        self._tagdata = value
        self._taglen = len(self._tagdata)

    def size(self):
        return 4 + len(self._tagdata)

    @classmethod
    def default(cls):
        tmp = cls()
        tmp.tag = 1
        tmp.tagdata = b"\x00" * 8
        return tmp

    def to_bytes(self) -> bytes:
        b = self._tag.to_bytes(2, byteorder="big", signed=True)
        b += self._taglen.to_bytes(2, byteorder="big", signed=True)
        b += self._tagdata
        return b


class Headers:
    _headerslen: int = 0  # uint16_t
    _headers: list[Header] = None

    def __init__(self):
        self._headers = list[Header]()
        self._headerslen = 0

    @property
    def headers(self) -> list[Header]:
        return self._headers

    @property
    def headerslen(self) -> int:
        return self._headerslen

    def add(self, value):
        self._headers.append(value)
        self._headerslen += value.size()

    def clear(self):
        self._headers = list[Header]()
        self._headerslen = 0

    def size(self):
        total = 0
        for v in self._headers:
            total += v.size()
        return total

    def to_bytes(self) -> bytes:
        b = self._headerslen.to_bytes(2, byteorder="big", signed=True)
        for v in self._headers:
            b += v.to_bytes()
        return b


class Keyblock:
    _keytype: int = None  # uint16_t
    _etype: int = None  # uint16_t
    _keylen: int = None  # uint16_t
    _keyvalue: bytes = None  # uint8_t[uint16_t]

    def __init__(self, key: EncryptionKey):
        self._keytype = key.keytype.value
        self._etype = 0  # only present in version 0x0503
        self._keyvalue = key.keyvalue
        self._keylen = len(self._keyvalue)

    @property
    def keytype(self) -> int:
        return self._keytype

    @keytype.setter
    def keytype(self, value) -> None:
        self._keytype = value

    @property
    def etype(self) -> int:
        return self._etype

    @etype.setter
    def etype(self, value) -> None:
        self._etype = value

    @property
    def keylen(self) -> int:
        return self._keylen

    @keylen.setter
    def keylen(self, value) -> None:
        self._keylen = value

    @property
    def keyvalue(self) -> bytes:
        return self._keyvalue

    @keyvalue.setter
    def keyvalue(self, value) -> None:
        self._keyvalue = value

    def to_bytes(self) -> bytes:
        b = self._keytype.to_bytes(2, byteorder="big", signed=True)
        b += self._etype.to_bytes(2, byteorder="big", signed=True)
        b += self._keylen.to_bytes(2, byteorder="big", signed=True)
        b += self._keyvalue
        return b


class Times:
    _authtime: int = 0  # uint32_t
    _starttime: int = 0  # uint32_t
    _endtime: int = 0  # uint32_t
    _renew_till: int = 0  # uint32_t

    def __init__(
        self,
        authtime: KerberosTime,
        starttime: KerberosTime,
        endtime: KerberosTime,
        renew_till: KerberosTime,
    ):
        if authtime is not None:
            self._authtime = int(authtime.to_asn1().native.timestamp())
        if starttime is not None:
            self._starttime = int(starttime.to_asn1().native.timestamp())
        if endtime is not None:
            self._endtime = int(endtime.to_asn1().native.timestamp())
        if renew_till is not None:
            self._renew_till = int(renew_till.to_asn1().native.timestamp())

    @property
    def authtime(self) -> int:
        return self._authtime

    @authtime.setter
    def authtime(self, value) -> None:
        self._authtime = value

    @property
    def starttime(self) -> int:
        return self._starttime

    @starttime.setter
    def starttime(self, value) -> None:
        self._starttime = value

    @property
    def endtime(self) -> int:
        return self._endtime

    @endtime.setter
    def endtime(self, value) -> None:
        self._endtime = value

    @property
    def renew_till(self) -> int:
        return self._renew_till

    @renew_till.setter
    def renew_till(self, value) -> None:
        self._renew_till = value

    def to_bytes(self) -> bytes:
        b = self._authtime.to_bytes(4, byteorder="big", signed=True)
        b += self._starttime.to_bytes(4, byteorder="big", signed=True)
        b += self._endtime.to_bytes(4, byteorder="big", signed=True)
        b += self._renew_till.to_bytes(4, byteorder="big", signed=True)
        return b


class Address:
    _addrtype: int = None  # uint16_t
    _addrdata: OctetString = None


class Authdata:
    _authtype: int = None  # uint16_t
    _authdata: OctetString = None


class Principal:
    _name_type: int = None  # uint32_t
    _num_components: int = None  # uint32_t
    _realm: OctetString = None
    _components: list[OctetString] = None

    def __init__(self, principal: PrincipalName, realm: Realm):
        self._components = list()
        self._name_type = principal.name_type.value
        self._num_components = len(principal.name_value.to_asn1().native)
        for v in principal.name_value.to_asn1().native:
            self._components.append(OctetString(v))
        self._realm = OctetString(realm.to_asn1().native)

    @property
    def name_type(self) -> int:
        return self._name_type

    @name_type.setter
    def name_type(self, value) -> None:
        self._name_type = value

    @property
    def num_components(self) -> int:
        return self._num_components

    @num_components.setter
    def num_components(self, value) -> None:
        self._num_components = value

    @property
    def realm(self) -> OctetString:
        return self._realm

    @realm.setter
    def realm(self, value) -> None:
        self._realm = value

    @property
    def components(self) -> list[OctetString]:
        return self._components

    @components.setter
    def components(self, value) -> None:
        self._components = value

    def to_bytes(self) -> bytes:
        b = self._name_type.to_bytes(4, byteorder="big", signed=True)
        b += self._num_components.to_bytes(4, byteorder="big", signed=True)
        b += self._realm.to_bytes()
        for v in self._components:
            b += v.to_bytes()
        return b


class DeltaTime:
    _time_offset: int = None  # uint32_t
    _usec_offset: int = None  # uint32_t


class Credential:
    _client: Principal = None
    _server: Principal = None
    _key: Keyblock = None
    _time: Times = None
    _is_skey: int = None  # uint8_t
    _tktflags: int = None  # uint32_t
    _num_address: int = None  # uint32_t
    _addrs: list[Address] = None
    _num_authdata: int = None  # uint32_t
    _authdata: list[Authdata] = None
    _ticket: OctetString = None
    _second_ticket: OctetString = None

    def __init__(self):
        self._addrs = list()
        self._authdata = list()

    @property
    def client(self) -> Principal:
        return self._client

    @client.setter
    def client(self, value) -> None:
        self._client = value

    @property
    def server(self) -> Principal:
        return self._server

    @server.setter
    def server(self, value) -> None:
        self._server = value

    @property
    def time(self) -> Times:
        return self._time

    @time.setter
    def time(self, value) -> None:
        self._time = value

    @property
    def key(self) -> Keyblock:
        return self._key

    @key.setter
    def key(self, value) -> None:
        self._key = value

    @property
    def is_skey(self) -> int:
        return self._is_skey

    @is_skey.setter
    def is_skey(self, value) -> None:
        self._is_skey = value

    @property
    def tktflags(self) -> int:
        return self._tktflags

    @tktflags.setter
    def tktflags(self, value) -> None:
        if isinstance(value, TicketFlags):
            self.tktflags = value.to_asn1().cast(core.IntegerBitString).native
        else:
            self._tktflags = value

    @property
    def num_address(self) -> int:
        return self._num_address

    @num_address.setter
    def num_address(self, value) -> None:
        self._num_address = value

    @property
    def num_authdata(self) -> int:
        return self._num_authdata

    @num_authdata.setter
    def num_authdata(self, value) -> None:
        self._num_authdata = value

    @property
    def ticket(self) -> OctetString:
        return self._ticket

    @ticket.setter
    def ticket(self, value) -> None:
        self._ticket = value

    @property
    def second_ticket(self) -> OctetString:
        return self._second_ticket

    @second_ticket.setter
    def second_ticket(self, value) -> None:
        self._second_ticket = value

    def to_bytes(self) -> bytes:
        b = self._client.to_bytes()
        b += self._server.to_bytes()
        b += self._key.to_bytes()
        b += self._time.to_bytes()
        b += self._is_skey.to_bytes(1)
        b += self._tktflags.to_bytes(4, byteorder="big", signed=True)
        b += self._num_address.to_bytes(4, byteorder="big", signed=True)
        for v in self._addrs:
            b += v.to_bytes()
        b += self._num_authdata.to_bytes(4, byteorder="big", signed=True)
        for v in self._authdata:
            b += v.to_bytes()
        b += self._ticket.to_bytes()
        b += self._second_ticket.to_bytes()
        return b


class Credentials:
    _credentials: list[Credential] = None

    def __init__(self):
        self._credentials = list[Credential]()

    def add(self, value):
        self._credentials.append(value)

    def clear(self):
        self._credentials = list[Credential]()

    @property
    def credentials(self) -> list[Credential]:
        return self._credentials

    def to_bytes(self) -> bytes:
        b = b""
        for v in self._credentials:
            b += v.to_bytes()
        return b


# https://repo.or.cz/w/krb5dissect.git/blob_plain/HEAD:/ccache.txt
class Ccache:
    _file_format_version: int = 0x0504  # uint16_t
    _headers: Headers = None
    _primary_principal: Principal = None
    _credentials: Credentials = None

    def __init__(self):
        self._headers = Headers()
        self._credentials = Credentials()
        self._headers.add(Header.default())

    @property
    def headers(self) -> list[Header]:
        return self._headers

    @property
    def primary_principal(self) -> Principal:
        return self._primary_principal

    @property
    def credentials(self) -> Credentials:
        return self._credentials

    def set_tgt(self, kdc_rep: KdcRep, kdc_enc_part: EncKdcRepPart):
        """
        Set TGT as main credentials in CCACHE structure
        """
        self._credentials = Credentials()
        # set primary principal
        self._primary_principal = Principal(kdc_rep.cname, kdc_rep.crealm)
        # create credential
        c = Credential()
        c.client = Principal(kdc_rep.cname, kdc_rep.crealm)
        c.server = Principal(kdc_enc_part.sname, kdc_enc_part.srealm)
        c.time = Times(
            kdc_enc_part.authtime,
            kdc_enc_part.starttime,
            kdc_enc_part.endtime,
            kdc_enc_part.renew_till,
        )
        c.key = Keyblock(kdc_enc_part.key)
        c.is_skey = 0  # TODO - research
        c.tktflags = kdc_enc_part.flags
        c.num_address = 0
        c.num_authdata = 0
        c.ticket = OctetString(kdc_rep.ticket.to_asn1().dump())
        c.second_ticket = OctetString()
        self._credentials.add(c)

    def serialize(self) -> bytes:
        b = self._file_format_version.to_bytes(2, byteorder="big", signed=True)
        b += self._headers.to_bytes()
        b += self._primary_principal.to_bytes()
        b += self._credentials.to_bytes()
        return b

    def to_file(self, path) -> None:
        with open(path, "wb") as f:
            f.write(self.serialize())
