from asn1crypto import core

# explicit tag for ASN1
EXPLICIT = 'explicit'

# https://www.rfc-editor.org/rfc/rfc4120#section-5.2.4
class Int32Asn1(core.Integer):
    """
    Int32           ::= INTEGER (-2147483648..2147483647) -- signed values representable in 32 bits
    """

# https://www.rfc-editor.org/rfc/rfc4120#section-5.2.4
class UInt32Asn1(core.Integer):
    """
    UInt32          ::= INTEGER (0..4294967295) -- unsigned 32 bit values
    """

# https://www.rfc-editor.org/rfc/rfc4120#section-5.2.4
class MicrosecondsAsn1(core.Integer):
    """
    Microseconds    ::= INTEGER (0..999999) -- microseconds
    """

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