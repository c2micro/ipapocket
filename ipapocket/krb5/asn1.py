from asn1crypto import core
import ctypes
from ipapocket.exceptions.exceptions import Asn1ConstrainedViolation
from ipapocket.krb5.constants import KdcOptionsTypes

# explicit tag for ASN1
EXPLICIT = 'explicit'

# https://www.rfc-editor.org/rfc/rfc4120#section-5.2.4
class Int32Asn1(core.Integer):
    """
    Int32           ::= INTEGER (-2147483648..2147483647) -- signed values representable in 32 bits
    """
    def set(self, value):
        if value not in range(-2147483648, 2147483647):
            raise Asn1ConstrainedViolation("Invalid value {} for Int32 ASN1 type".format(value))
        return super().set(value)

# https://www.rfc-editor.org/rfc/rfc4120#section-5.2.4
class UInt32Asn1(core.Integer):
    """
    UInt32          ::= INTEGER (0..4294967295) -- unsigned 32 bit values
    """
    def set(self, value):
        if value not in range(0, 4294967295):
            raise Asn1ConstrainedViolation("Invalid value {} for UInt32 ASN1 type".format(value))
        return super().set(value)

# https://www.rfc-editor.org/rfc/rfc4120#section-5.2.4
class MicrosecondsAsn1(core.Integer):
    """
    Microseconds    ::= INTEGER (0..999999) -- microseconds
    """
    def set(self, value):
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
class KerberosFlags(core.BitString):
    """
    KerberosFlags   ::= BIT STRING (SIZE (32..MAX))
                       -- minimum number of bits shall be sent,
                       -- but no fewer than 32
    """

class KdcOptionsAsn1(KerberosFlags):
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