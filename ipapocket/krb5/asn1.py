from asn1crypto import core
import ctypes
from ipapocket.exceptions.exceptions import Asn1ConstrainedViolation
from ipapocket.krb5.constants import KdcOptionsTypes, MessageTypes

# explicit tag for ASN1
EXPLICIT = 'explicit'

UNIVERSAL = 0
APPLICATION = 1
CONTEXT = 2

# https://www.rfc-editor.org/rfc/rfc4120#section-5.2.4
class Int32Asn1(core.Integer):
    """
    Int32           ::= INTEGER (-2147483648..2147483647) -- signed values representable in 32 bits
    """

    def set(self, value):
        """
            Validate that value in specified range
        """
        if value not in range(-2147483648, 2147483647):
            raise Asn1ConstrainedViolation("Invalid value {} for Int32 ASN1 type".format(value))
        return super().set(value)


# https://www.rfc-editor.org/rfc/rfc4120#section-5.2.4
class UInt32Asn1(core.Integer):
    """
    UInt32          ::= INTEGER (0..4294967295) -- unsigned 32 bit values
    """

    def set(self, value):
        """
            Validate that value in specified range
        """
        if value not in range(0, 4294967295):
            raise Asn1ConstrainedViolation("Invalid value {} for UInt32 ASN1 type".format(value))
        return super().set(value)


# https://www.rfc-editor.org/rfc/rfc4120#section-5.2.4
class MicrosecondsAsn1(core.Integer):
    """
    Microseconds    ::= INTEGER (0..999999) -- microseconds
    """

    def set(self, value):
        """
            Validate that value in specified range
        """
        if value not in range(0, 999999):
            raise Asn1ConstrainedViolation("Invalid value {} for Microseconds ASN1 type".format(value))
        return super().set(value)


# https://www.rfc-editor.org/rfc/rfc4120#appendix-A
class KerberosStringAsn1(core.GeneralString):
    """
    KerberosString  ::= GeneralString (IA5String)
    """

    _child_spec = core.IA5String


# https://www.rfc-editor.org/rfc/rfc4120#appendix-A
class RealmAsn1(KerberosStringAsn1):
    """
    Realm           ::= KerberosString
    """

    pass

# type to store sequence of strings
class KerberosStringsAsn1(core.SequenceOf):
    _child_spec = KerberosStringAsn1


# https://www.rfc-editor.org/rfc/rfc4120#section-5.2.2
class PrincipalNameAsn1(core.Sequence):
    """
    Realm           ::= KerberosString

    PrincipalName   ::= SEQUENCE {
           name-type       [0] Int32,
           name-string     [1] SEQUENCE OF KerberosString
    }
    """

    _fields = [
        ('name-type', Int32Asn1, {'tag_type': EXPLICIT, 'tag': 0}),
        ('name-string', KerberosStringsAsn1, {'tag_type': EXPLICIT, 'tag': 1}),
    ]


# https://www.rfc-editor.org/rfc/rfc4120#section-5.2.8
class KerberosFlagsAsn1(core.BitString):
    """
    KerberosFlags   ::= BIT STRING (SIZE (32..MAX))
                       -- minimum number of bits shall be sent,
                       -- but no fewer than 32
    """

    pass


# https://www.rfc-editor.org/rfc/rfc4120#section-5.4.1
class KdcOptionsAsn1(KerberosFlagsAsn1):
    """
    KDCOptions      ::= KerberosFlags
        -- reserved(0),
        -- forwardable(1),
        -- forwarded(2),
        -- proxiable(3),
        -- proxy(4),
        -- allow-postdate(5),
        -- postdated(6),
        -- unused7(7),
        -- renewable(8),
        -- unused9(9),
        -- unused10(10),
        -- opt-hardware-auth(11),
        -- unused12(12),
        -- unused13(13),
        -- 15 is reserved for canonicalize
        -- unused15(15),
        -- 26 was unused in 1510
        -- disable-transited-check(26),
        -- renewable-ok(27),
        -- enc-tkt-in-skey(28),
        -- renew(30),
        -- validate(31)
    """

    pass


# https://www.rfc-editor.org/rfc/rfc4120#appendix-A
class RealmAsn1(KerberosStringAsn1):
    """
    Realm           ::= KerberosString
    """

    pass


# https://www.rfc-editor.org/rfc/rfc4120#section-5.2.3
class KerberosTimeAsn1(core.GeneralizedTime):
    """
    KerberosTime ::= GeneralizedTime -- with no fractional seconds
    """

    pass


# sequence of integers to store types of encryption algos
class EncTypesAsn1(core.SequenceOf):
    _child_spec = core.Integer


# https://www.rfc-editor.org/rfc/rfc4120#section-5.2.5
class HostAddressAsn1(core.Sequence):
    """
    HostAddress     ::= SEQUENCE  {
        addr-type       [0] Int32,
        address         [1] OCTET STRING
    }
    """

    _fields = [
        ('addr-type', Int32Asn1, {'tag_type': EXPLICIT, 'tag': 0}),
        ('address', core.OctetString, {'tag_type': EXPLICIT, 'tag': 1}),
    ]


# https://www.rfc-editor.org/rfc/rfc4120#section-5.2.5
class HostAddressesAsn1(core.SequenceOf):
    """
    -- NOTE: HostAddresses is always used as an OPTIONAL field and
    -- should not be empty.
    HostAddresses   -- NOTE: subtly different from rfc1510,
                   -- but has a value mapping and encodes the same
           ::= SEQUENCE OF HostAddress
    """

    _child_spec = HostAddressAsn1


# https://www.rfc-editor.org/rfc/rfc4120#section-5.2.9
class EncryptedDataAsn1(core.Sequence):
    """
    EncryptedData   ::= SEQUENCE {
           etype   [0] Int32 -- EncryptionType --,
           kvno    [1] UInt32 OPTIONAL,
           cipher  [2] OCTET STRING -- ciphertext
    }
    """

    _fields = [
        ('etype', Int32Asn1, {'tag_type': EXPLICIT, 'tag': 0}),
        ('kvno', UInt32Asn1, {'tag_type': EXPLICIT, 'tag': 1, 'optional': True}),
        ('cipher', core.OctetString, {'tag_type': EXPLICIT, 'tag': 2}),
    ]


# https://www.rfc-editor.org/rfc/rfc4120#appendix-A
class TicketAsn1(core.Sequence):
    """
    Ticket          ::= [APPLICATION 1] SEQUENCE {
           tkt-vno         [0] INTEGER (5),
           realm           [1] Realm,
           sname           [2] PrincipalName,
           enc-part        [3] EncryptedData -- EncTicketPart
    }
    """

    explicit = (APPLICATION, 1)

    _fields = [
        ('tkt-vno', Int32Asn1, {'tag_type': EXPLICIT, 'tag': 0}),
        ('realm', RealmAsn1, {'tag_type': EXPLICIT, 'tag': 1}),
        ('sname', PrincipalNameAsn1, {'tag_type': EXPLICIT, 'tag': 2}),
        ('enc-part', EncryptedDataAsn1, {'tag_type': EXPLICIT, 'tag': 3}),
    ]


# sequence of tickets
class TicketsAsn1(core.SequenceOf):
    _child_spec = TicketAsn1


# https://www.rfc-editor.org/rfc/rfc4120#appendix-A
class KdcReqBodyAsn1(core.Sequence):
    """
    KDC-REQ-BODY    ::= SEQUENCE {
        kdc-options             [0] KDCOptions,
        cname                   [1] PrincipalName OPTIONAL
                                    -- Used only in AS-REQ --,
        realm                   [2] Realm
                                    -- Server's realm
                                    -- Also client's in AS-REQ --,
        sname                   [3] PrincipalName OPTIONAL,
        from                    [4] KerberosTime OPTIONAL,
        till                    [5] KerberosTime,
        rtime                   [6] KerberosTime OPTIONAL,
        nonce                   [7] UInt32,
        etype                   [8] SEQUENCE OF Int32 -- EncryptionType
                                    -- in preference order --,
        addresses               [9] HostAddresses OPTIONAL,
        enc-authorization-data  [10] EncryptedData OPTIONAL
                                    -- AuthorizationData --,
        additional-tickets      [11] SEQUENCE OF Ticket OPTIONAL
                                        -- NOTE: not empty
    """
    
    _fields = [
        ('kdc-options', KdcOptionsAsn1, {'tag_type': EXPLICIT, 'tag': 0}),
        ('cname', PrincipalNameAsn1, {'tag_type': EXPLICIT, 'tag': 1, 'optional': True}),
        ('realm', RealmAsn1, {'tag_type': EXPLICIT, 'tag': 2}),
        ('sname', PrincipalNameAsn1, {'tag_type': EXPLICIT, 'tag': 3, 'optional': True}),
        ('from', KerberosTimeAsn1, {'tag_type': EXPLICIT, 'tag': 4, 'optional': True}),
        ('till', KerberosTimeAsn1, {'tag_type': EXPLICIT, 'tag': 5}),
        ('rtime', KerberosTimeAsn1, {'tag_type': EXPLICIT, 'tag': 6, 'optional': True}),
        ('nonce', UInt32Asn1, {'tag_type': EXPLICIT, 'tag': 7}),
        ('etype', EncTypesAsn1, {'tag_type': EXPLICIT, 'tag': 8}),
        ('addresses', HostAddressesAsn1, {'tag_type': EXPLICIT, 'tag': 9, 'optional': True}),
        ('enc-authorization-data', EncryptedDataAsn1, {'tag_type': EXPLICIT, 'tag': 10, 'optional': True}),
        ('additional-tickets', TicketsAsn1, {'tag_type': EXPLICIT, 'tag': 11, 'optional': True}),
    ]


# https://www.rfc-editor.org/rfc/rfc4120#appendix-A
class PaDataAsn1(core.Sequence):
    """
    PA-DATA         ::= SEQUENCE {
        -- NOTE: first tag is [1], not [0]
        padata-type     [1] Int32,
        padata-value    [2] OCTET STRING -- might be encoded AP-REQ
    }
    """

    _fields = [
        ('padata-type', Int32Asn1, {'tag_type': EXPLICIT, 'tag': 1}),
        ('padata-value', core.OctetString, {'tag_type': EXPLICIT, 'tag': 2}),
    ]


# sequence of preauthentication data sets
class PaDatasAsn1(core.SequenceOf):
    _child_spec = PaDataAsn1


# https://www.rfc-editor.org/rfc/rfc4120#appendix-A
class KdcReqAsn1(core.Sequence):
    """
    KDC-REQ         ::= SEQUENCE {
        -- NOTE: first tag is [1], not [0]
        pvno            [1] INTEGER (5) ,
        msg-type        [2] INTEGER (10 -- AS -- | 12 -- TGS --),
        padata          [3] SEQUENCE OF PA-DATA OPTIONAL
                            -- NOTE: not empty --,
        req-body        [4] KDC-REQ-BODY
    }
    """

    _fields = [
        ('pvno', Int32Asn1, {'tag_type': EXPLICIT, 'tag': 1}),
        ('msg-type', Int32Asn1, {'tag_type': EXPLICIT, 'tag': 2}),
        ('padata', PaDatasAsn1, {'tag_type': EXPLICIT, 'tag': 3, 'optional': True}),
        ('req-body', KdcReqBodyAsn1, {'tag_type': EXPLICIT, 'tag': 4}),
    ]


# https://www.rfc-editor.org/rfc/rfc4120#appendix-A
class AsReqAsn1(KdcReqAsn1):
    explicit = (APPLICATION, MessageTypes.KRB_AS_REQ.value)