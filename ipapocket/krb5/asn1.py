from asn1crypto import core
from ipapocket.exceptions.exceptions import Asn1ConstrainedViolation
from ipapocket.krb5.constants import (
    MessageTypes,
    ApplicationTagNumbers,
    MIN_INT32,
    MAX_INT32,
    MIN_UINT32,
    MAX_UINT32,
    MIN_MICROSECONDS,
    MAX_MICROSECONDS,
)
from ipapocket.krb5.fields import *

# explicit tag for ASN1
EXPLICIT = "explicit"

UNIVERSAL = 0
APPLICATION = 1
CONTEXT = 2


# https://www.rfc-editor.org/rfc/rfc4120#section-5.2.4
# wrapped by ipapocket.krb5.objects.Int32
class Int32Asn1(core.Integer):
    """
    Int32           ::= INTEGER (-2147483648..2147483647) -- signed values representable in 32 bits
    """

    def set(self, value):
        """
        Validate that value in specified range
        """
        if value not in range(MIN_INT32, MAX_INT32 + 1):
            raise Asn1ConstrainedViolation(
                "Invalid value {} for Int32 ASN1 type".format(value)
            )
        return super().set(value)


# https://www.rfc-editor.org/rfc/rfc4120#section-5.2.4
# wrapped by ipapocket.krb5.objects.UInt32
class UInt32Asn1(core.Integer):
    """
    UInt32          ::= INTEGER (0..4294967295) -- unsigned 32 bit values
    """

    def set(self, value):
        """
        Validate that value in specified range
        """
        if value not in range(MIN_UINT32, MAX_UINT32 + 1):
            raise Asn1ConstrainedViolation(
                "Invalid value {} for UInt32 ASN1 type".format(value)
            )
        return super().set(value)


# https://www.rfc-editor.org/rfc/rfc4120#section-5.2.4
# wrapped by ipapocket.krb5.objects.Microseconds
class MicrosecondsAsn1(core.Integer):
    """
    Microseconds    ::= INTEGER (0..999999) -- microseconds
    """

    def set(self, value):
        """
        Validate that value in specified range
        """
        if value not in range(MIN_MICROSECONDS, MAX_MICROSECONDS + 1):
            raise Asn1ConstrainedViolation(
                "Invalid value {} for Microseconds ASN1 type".format(value)
            )
        return super().set(value)


# https://www.rfc-editor.org/rfc/rfc4120#appendix-A
# wrapped by ipapocket.krb5.objects.KerberosString
class KerberosStringAsn1(core.GeneralString):
    """
    KerberosString  ::= GeneralString (IA5String)
    """

    _child_spec = core.IA5String


# https://www.rfc-editor.org/rfc/rfc4120#appendix-A
# wrapped by ipapocket.krb5.objects.Realm
class RealmAsn1(KerberosStringAsn1):
    """
    Realm           ::= KerberosString
    """

    pass


# type to store sequence of strings
# wrapped by ipapocket.krb5.objects.KerberosStrings
class KerberosStringsAsn1(core.SequenceOf):
    _child_spec = KerberosStringAsn1


# https://www.rfc-editor.org/rfc/rfc4120#section-5.2.2
# wrapped by ipapocket.krb5.objects.Principalname
class PrincipalNameAsn1(core.Sequence):
    """
    Realm           ::= KerberosString

    PrincipalName   ::= SEQUENCE {
           name-type       [0] Int32,
           name-string     [1] SEQUENCE OF KerberosString
    }
    """

    _fields = [
        (PRINCIPAL_NAME_NAME_TYPE, Int32Asn1, {"tag_type": EXPLICIT, "tag": 0}),
        (
            PRINCIPAL_NAME_NAME_STRING,
            KerberosStringsAsn1,
            {"tag_type": EXPLICIT, "tag": 1},
        ),
    ]


# https://www.rfc-editor.org/rfc/rfc4120#section-5.2.8
# wrapped by ipapocket.krb5.objects.KerberosFlags
class KerberosFlagsAsn1(core.BitString):
    """
    KerberosFlags   ::= BIT STRING (SIZE (32..MAX))
                       -- minimum number of bits shall be sent,
                       -- but no fewer than 32
    """

    pass


# https://www.rfc-editor.org/rfc/rfc4120#section-5.4.1
# wrapped by ipapocket.krb5.objects.KdcOptions
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
# wrapped by ipapocket.krb5.objects.TicketFlags
class TicketFlagsAsn1(core.BitString):
    """
    TicketFlags     ::= KerberosFlags
        -- reserved(0),
        -- forwardable(1),
        -- forwarded(2),
        -- proxiable(3),
        -- proxy(4),
        -- may-postdate(5),
        -- postdated(6),
        -- invalid(7),
        -- renewable(8),
        -- initial(9),
        -- pre-authent(10),
        -- hw-authent(11),
        -- the following are new since 1510
        -- transited-policy-checked(12),
        -- ok-as-delegate(13)
    """

    pass


# https://www.rfc-editor.org/rfc/rfc4120#appendix-A
# wrapped by ipapocket.krb5.objects.Realm
class RealmAsn1(KerberosStringAsn1):
    """
    Realm           ::= KerberosString
    """

    pass


# https://www.rfc-editor.org/rfc/rfc4120#section-5.2.3
# wrapped by ipapocket.krb5.objects.KerberosTime
class KerberosTimeAsn1(core.GeneralizedTime):
    """
    KerberosTime ::= GeneralizedTime -- with no fractional seconds
    """

    pass


# sequence of integers to store types of encryption algos
# wrapped by ipapocket.krb5.objects.EncTypes
class EncTypesAsn1(core.SequenceOf):
    _child_spec = core.Integer


# https://www.rfc-editor.org/rfc/rfc4120#section-5.2.5
# wrapped by ipapocket.krb5.objects.HostAddress
class HostAddressAsn1(core.Sequence):
    """
    HostAddress     ::= SEQUENCE  {
        addr-type       [0] Int32,
        address         [1] OCTET STRING
    }
    """

    _fields = [
        (HOST_ADDRESS_ADDR_TYPE, Int32Asn1, {"tag_type": EXPLICIT, "tag": 0}),
        (HOST_ADDRESS_ADDRESS, core.OctetString, {"tag_type": EXPLICIT, "tag": 1}),
    ]


# https://www.rfc-editor.org/rfc/rfc4120#section-5.2.5
# wrapped by ipapocket.krb5.objects.HostAddresses
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
# wrapped by ipapocket.krb5.objects.EncryptedData
class EncryptedDataAsn1(core.Sequence):
    """
    EncryptedData   ::= SEQUENCE {
           etype   [0] Int32 -- EncryptionType --,
           kvno    [1] UInt32 OPTIONAL,
           cipher  [2] OCTET STRING -- ciphertext
    }
    """

    _fields = [
        (ENCRYPTED_DATA_ETYPE, Int32Asn1, {"tag_type": EXPLICIT, "tag": 0}),
        (
            ENCRYPTED_DATA_KVNO,
            UInt32Asn1,
            {"tag_type": EXPLICIT, "tag": 1, "optional": True},
        ),
        (ENCRYPTED_DATA_CIPHER, core.OctetString, {"tag_type": EXPLICIT, "tag": 2}),
    ]


# https://www.rfc-editor.org/rfc/rfc4120#appendix-A
# wrapped by ipapocket.kdb5.objects.Ticket
class TicketAsn1(core.Sequence):
    """
    Ticket          ::= [APPLICATION 1] SEQUENCE {
           tkt-vno         [0] INTEGER (5),
           realm           [1] Realm,
           sname           [2] PrincipalName,
           enc-part        [3] EncryptedData -- EncTicketPart
    }
    """

    explicit = (APPLICATION, ApplicationTagNumbers.TICKET.value)

    _fields = [
        (TICKET_TKT_VNO, Int32Asn1, {"tag_type": EXPLICIT, "tag": 0}),
        (TICKET_REALM, RealmAsn1, {"tag_type": EXPLICIT, "tag": 1}),
        (TICKET_SNAME, PrincipalNameAsn1, {"tag_type": EXPLICIT, "tag": 2}),
        (TICKET_ENC_PART, EncryptedDataAsn1, {"tag_type": EXPLICIT, "tag": 3}),
    ]


# sequence of tickets
# wrapped by ipapocket.krb5.objects.Tickets
class TicketsAsn1(core.SequenceOf):
    _child_spec = TicketAsn1


# https://www.rfc-editor.org/rfc/rfc4120#appendix-A
# wrapped by ipapocket.krb5.objects.KdcReqBody
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
        (KDC_REQ_BODY_KDC_OPTIONS, KdcOptionsAsn1, {"tag_type": EXPLICIT, "tag": 0}),
        (
            KDC_REQ_BODY_CNAME,
            PrincipalNameAsn1,
            {"tag_type": EXPLICIT, "tag": 1, "optional": True},
        ),
        (KDC_REQ_BODY_REALM, RealmAsn1, {"tag_type": EXPLICIT, "tag": 2}),
        (
            KDC_REQ_BODY_SNAME,
            PrincipalNameAsn1,
            {"tag_type": EXPLICIT, "tag": 3, "optional": True},
        ),
        (
            KDC_REQ_BODY_FROM,
            KerberosTimeAsn1,
            {"tag_type": EXPLICIT, "tag": 4, "optional": True},
        ),
        (KDC_REQ_BODY_TILL, KerberosTimeAsn1, {"tag_type": EXPLICIT, "tag": 5}),
        (
            KDC_REQ_BODY_RTIME,
            KerberosTimeAsn1,
            {"tag_type": EXPLICIT, "tag": 6, "optional": True},
        ),
        (KDC_REQ_BODY_NONCE, UInt32Asn1, {"tag_type": EXPLICIT, "tag": 7}),
        (KDC_REQ_BODY_ETYPE, EncTypesAsn1, {"tag_type": EXPLICIT, "tag": 8}),
        (
            KDC_REQ_BODY_ADDRESSES,
            HostAddressesAsn1,
            {"tag_type": EXPLICIT, "tag": 9, "optional": True},
        ),
        (
            KDC_REQ_BODY_ENC_AUTH_DATA,
            EncryptedDataAsn1,
            {"tag_type": EXPLICIT, "tag": 10, "optional": True},
        ),
        (
            KDC_REQ_BODY_ADDITIONAL_TICKETS,
            TicketsAsn1,
            {"tag_type": EXPLICIT, "tag": 11, "optional": True},
        ),
    ]


# https://www.rfc-editor.org/rfc/rfc4120#appendix-A
# wrapped by ipapocket.krb5.objects.PaData
class PaDataAsn1(core.Sequence):
    """
    PA-DATA         ::= SEQUENCE {
        -- NOTE: first tag is [1], not [0]
        padata-type     [1] Int32,
        padata-value    [2] OCTET STRING -- might be encoded AP-REQ
    }
    """

    _fields = [
        (PADATA_PADATA_TYPE, Int32Asn1, {"tag_type": EXPLICIT, "tag": 1}),
        (PADATA_PADATA_VALUE, core.OctetString, {"tag_type": EXPLICIT, "tag": 2}),
    ]


# sequence of preauthentication data sets
# wrapped by ipapocket.krb5.objects.PaDatas
class PaDatasAsn1(core.SequenceOf):
    _child_spec = PaDataAsn1


# https://www.rfc-editor.org/rfc/rfc4120#appendix-A
# wrapped by ipapocket.krb5.objects.KdcReq
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
        (KDC_REQ_PVNO, Int32Asn1, {"tag_type": EXPLICIT, "tag": 1}),
        (KDC_REQ_MSG_TYPE, Int32Asn1, {"tag_type": EXPLICIT, "tag": 2}),
        (
            KDC_REQ_PADATA,
            PaDatasAsn1,
            {"tag_type": EXPLICIT, "tag": 3, "optional": True},
        ),
        (KDC_REQ_REQ_BODY, KdcReqBodyAsn1, {"tag_type": EXPLICIT, "tag": 4}),
    ]


# https://www.rfc-editor.org/rfc/rfc4120#appendix-A
# wrapped by ipapocket.krb5.objects.AsReq
class AsReqAsn1(KdcReqAsn1):
    explicit = (APPLICATION, ApplicationTagNumbers.AS_REQ.value)


# https://www.rfc-editor.org/rfc/rfc4120#appendix-A
# wrapped by ipapocket.krb5.objects.AsReq
class TgsReqAsn1(KdcReqAsn1):
    explicit = (APPLICATION, ApplicationTagNumbers.TGS_REQ.value)


# https://www.rfc-editor.org/rfc/rfc4120#section-5.5.1
# wrapped by ipapocket.krb5.objects.ApOptions
class ApOptionsAsn1(KerberosFlagsAsn1):
    """
    APOptions       ::= KerberosFlags
           -- reserved(0),
           -- use-session-key(1),
           -- mutual-required(2)
    """

    pass


# https://www.rfc-editor.org/rfc/rfc4120#section-5.5.1
# wrapped by ipapocket.krb5.objects.ApReq
class ApReqAsn1(core.Sequence):
    """
    AP-REQ          ::= [APPLICATION 14] SEQUENCE {
           pvno            [0] INTEGER (5),
           msg-type        [1] INTEGER (14),
           ap-options      [2] APOptions,
           ticket          [3] Ticket,
           authenticator   [4] EncryptedData -- Authenticator
    }
    """

    explicit = (APPLICATION, ApplicationTagNumbers.AP_REQ.value)

    _fields = [
        (AP_REQ_PVNO, Int32Asn1, {"tag_type": EXPLICIT, "tag": 0}),
        (AP_REQ_MSG_TYPE, Int32Asn1, {"tag_type": EXPLICIT, "tag": 1}),
        (AP_REQ_AP_OPTIONS, ApOptionsAsn1, {"tag_type": EXPLICIT, "tag": 2}),
        (AP_REQ_TICKET, TicketAsn1, {"tag_type": EXPLICIT, "tag": 3}),
        (AP_REQ_AUTHENTICATOR, EncryptedDataAsn1, {"tag_type": EXPLICIT, "tag": 4}),
    ]


# https://www.rfc-editor.org/rfc/rfc4120#section-5.2.9
# wrapped by ipapocket.krb5.objects.EncryptionKey
class EncryptionKeyAsn1(core.Sequence):
    """
    EncryptionKey   ::= SEQUENCE {
           keytype         [0] Int32 -- actually encryption type --,
           keyvalue        [1] OCTET STRING
    }
    """

    _fields = [
        (ENCRYPTION_KEY_KEYTYPE, Int32Asn1, {"tag_type": EXPLICIT, "tag": 0}),
        (ENCRYPTION_KEY_KEYVALUE, core.OctetString, {"tag_type": EXPLICIT, "tag": 1}),
    ]


# https://www.rfc-editor.org/rfc/rfc4120#appendix-A
# wrapped by ipapocket.krb5.objects.AuthorizationDataElement
class AuthorizationDataElementAsn1(core.Sequence):
    """
    AuthorizationData       ::= SEQUENCE OF SEQUENCE {
        ad-type         [0] Int32,
        ad-data         [1] OCTET STRING
    }
    """

    _fields = [
        (AUTHORIZATION_DATA_AD_TYPE, Int32Asn1, {"tag_type": EXPLICIT, "tag": 0}),
        (
            AUTHORIZATION_DATA_AD_DATA,
            core.OctetString,
            {"tag_type": EXPLICIT, "tag": 1},
        ),
    ]


# sequence of authorization data
# wrapped by ipapocket.krb5.objects.AuthorizationData
class AuthorizationDataAsn1(core.SequenceOf):
    _child_spec = AuthorizationDataElementAsn1


# https://www.rfc-editor.org/rfc/rfc4120#appendix-A
# wrapped by ipapocket.krb5.objects.Checksum
class ChecksumAsn1(core.Sequence):
    """
    Checksum        ::= SEQUENCE {
        cksumtype       [0] Int32,
        checksum        [1] OCTET STRING
    }
    """

    _fields = [
        (CHECKSUM_CKSUMTYPE, Int32Asn1, {"tag_type": EXPLICIT, "tag": 0}),
        (CHECKSUM_CHECKSUM, core.OctetString, {"tag_type": EXPLICIT, "tag": 1}),
    ]


# https://www.rfc-editor.org/rfc/rfc4120#section-5.5.1
# wrapped by ipapocket.krb5.objects.Authenticator
class AuthenticatorAsn1(core.Sequence):
    """
    Authenticator   ::= [APPLICATION 2] SEQUENCE  {
           authenticator-vno       [0] INTEGER (5),
           crealm                  [1] Realm,
           cname                   [2] PrincipalName,
           cksum                   [3] Checksum OPTIONAL,
           cusec                   [4] Microseconds,
           ctime                   [5] KerberosTime,
           subkey                  [6] EncryptionKey OPTIONAL,
           seq-number              [7] UInt32 OPTIONAL,
           authorization-data      [8] AuthorizationData OPTIONAL
    }
    """

    explicit = (APPLICATION, ApplicationTagNumbers.AUTHENTICATOR.value)

    _fields = [
        (AUTHENTICATOR_AUTHENTICATOR_VNO, Int32Asn1, {"tag_type": EXPLICIT, "tag": 0}),
        (AUTHENTICATOR_CREALM, RealmAsn1, {"tag_type": EXPLICIT, "tag": 1}),
        (AUTHENTICATOR_CNAME, PrincipalNameAsn1, {"tag_type": EXPLICIT, "tag": 2}),
        (
            AUTHENTICATOR_CKSUM,
            ChecksumAsn1,
            {"tag_type": EXPLICIT, "tag": 3, "optional": True},
        ),
        (AUTHENTICATOR_CUSEC, MicrosecondsAsn1, {"tag_type": EXPLICIT, "tag": 4}),
        (AUTHENTICATOR_CTIME, KerberosTimeAsn1, {"tag_type": EXPLICIT, "tag": 5}),
        (
            AUTHENTICATOR_SUBKEY,
            EncryptionKeyAsn1,
            {"tag_type": EXPLICIT, "tag": 6, "optional": True},
        ),
        (
            AUTHENTICATOR_SEQ_NUMBER,
            UInt32Asn1,
            {"tag_type": EXPLICIT, "tag": 7, "optional": True},
        ),
        (
            AUTHENTICATOR_AUTHORIZATION_DATA,
            AuthorizationDataAsn1,
            {"tag_type": EXPLICIT, "tag": 8, "optional": True},
        ),
    ]


# https://www.rfc-editor.org/rfc/rfc4120#appendix-A
# wrapped by ipapocket.krb5.objects.LastReq
class LastReqAsn1(core.Sequence):
    """
    LastReq         ::=     SEQUENCE OF SEQUENCE {
           lr-type         [0] Int32,
           lr-value        [1] KerberosTime
    }
    """

    _fields = [
        (LAST_REQ_LR_TYPE, Int32Asn1, {"tag_type": EXPLICIT, "tag": 0}),
        (LAST_REQ_LR_VALUE, KerberosTimeAsn1, {"tag_type": EXPLICIT, "tag": 1}),
    ]


# type to hold sequences of LastReq
# wrapped by ipapocket.krb5.objects.LastReqs
class LastReqsAsn1(core.SequenceOf):
    _child_spec = LastReqAsn1


# https://www.rfc-editor.org/rfc/rfc4120#appendix-A
# wrapped by ipapocket.krb5.objects.EncKdcRepPart
class EncKdcRepPartAsn1(core.Sequence):
    """
    EncKDCRepPart   ::= SEQUENCE {
        key             [0] EncryptionKey,
        last-req        [1] LastReq,
        nonce           [2] UInt32,
        key-expiration  [3] KerberosTime OPTIONAL,
        flags           [4] TicketFlags,
        authtime        [5] KerberosTime,
        starttime       [6] KerberosTime OPTIONAL,
        endtime         [7] KerberosTime,
        renew-till      [8] KerberosTime OPTIONAL,
        srealm          [9] Realm,
        sname           [10] PrincipalName,
        caddr           [11] HostAddresses OPTIONAL
    }
    """

    _fields = [
        (ENC_KDC_REP_PART_KEY, EncryptionKeyAsn1, {"tag_type": EXPLICIT, "tag": 0}),
        (ENC_KDC_REP_PART_LAST_REQ, LastReqsAsn1, {"tag_type": EXPLICIT, "tag": 1}),
        (ENC_KDC_REP_PART_NONCE, Int32Asn1, {"tag_type": EXPLICIT, "tag": 2}),
        (
            ENC_KDC_REP_PART_KEY_EXPIRATION,
            KerberosTimeAsn1,
            {"tag_type": EXPLICIT, "tag": 3, "optional": True},
        ),
        (ENC_KDC_REP_PART_FLAGS, TicketFlagsAsn1, {"tag_type": EXPLICIT, "tag": 4}),
        (ENC_KDC_REP_PART_AUTHTIME, KerberosTimeAsn1, {"tag_type": EXPLICIT, "tag": 5}),
        (
            ENC_KDC_REP_PART_STARTTIME,
            KerberosTimeAsn1,
            {"tag_type": EXPLICIT, "tag": 6, "optional": True},
        ),
        (ENC_KDC_REP_PART_ENDTIME, KerberosTimeAsn1, {"tag_type": EXPLICIT, "tag": 7}),
        (
            ENC_KDC_REP_PART_RENEW_TILL,
            KerberosTimeAsn1,
            {"tag_type": EXPLICIT, "tag": 8, "optional": True},
        ),
        (ENC_KDC_REP_PART_SREALM, RealmAsn1, {"tag_type": EXPLICIT, "tag": 9}),
        (ENC_KDC_REP_PART_SNAME, PrincipalNameAsn1, {"tag_type": EXPLICIT, "tag": 10}),
        (
            ENC_KDC_REP_PART_CADDR,
            HostAddressesAsn1,
            {"tag_type": EXPLICIT, "tag": 11, "optional": True},
        ),
    ]


# https://www.rfc-editor.org/rfc/rfc4120#appendix-A
# https://www.rfc-editor.org/rfc/rfc4120#section-5.4.2
# wrapped by ipapocket.krb5.objects.KdcRep
class KdcRepAsn1(core.Sequence):
    """
    KDC-REP         ::= SEQUENCE {
        pvno            [0] INTEGER (5),
        msg-type        [1] INTEGER (11 -- AS -- | 13 -- TGS --),
        padata          [2] SEQUENCE OF PA-DATA OPTIONAL
                                -- NOTE: not empty --,
        crealm          [3] Realm,
        cname           [4] PrincipalName,
        ticket          [5] Ticket,
        enc-part        [6] EncryptedData
                                -- EncASRepPart or EncTGSRepPart,
                                -- as appropriate
    }
    """

    _fields = [
        (KDC_REP_PVNO, Int32Asn1, {"tag_type": EXPLICIT, "tag": 0}),
        (KDC_REP_MSG_TYPE, Int32Asn1, {"tag_type": EXPLICIT, "tag": 1}),
        (
            KDC_REP_PADATA,
            PaDatasAsn1,
            {"tag_type": EXPLICIT, "tag": 2, "optional": True},
        ),
        (KDC_REP_CREALM, RealmAsn1, {"tag_type": EXPLICIT, "tag": 3}),
        (KDC_REP_CNAME, PrincipalNameAsn1, {"tag_type": EXPLICIT, "tag": 4}),
        (KDC_REP_TICKET, TicketAsn1, {"tag_type": EXPLICIT, "tag": 5}),
        (KDC_REP_ENC_PART, EncryptedDataAsn1, {"tag_type": EXPLICIT, "tag": 6}),
    ]


# https://www.rfc-editor.org/rfc/rfc4120#section-5.9.1
# wrapped by ipapocket.krb5.objects.KrbError
class KrbErrorAsn1(core.Sequence):
    """
    KRB-ERROR       ::= [APPLICATION 30] SEQUENCE {
           pvno            [0] INTEGER (5),
           msg-type        [1] INTEGER (30),
           ctime           [2] KerberosTime OPTIONAL,
           cusec           [3] Microseconds OPTIONAL,
           stime           [4] KerberosTime,
           susec           [5] Microseconds,
           error-code      [6] Int32,
           crealm          [7] Realm OPTIONAL,
           cname           [8] PrincipalName OPTIONAL,
           realm           [9] Realm -- service realm --,
           sname           [10] PrincipalName -- service name --,
           e-text          [11] KerberosString OPTIONAL,
           e-data          [12] OCTET STRING OPTIONAL
    }
    """

    explicit = (APPLICATION, ApplicationTagNumbers.KRB_ERROR.value)

    _fields = [
        (KRB_ERROR_PVNO, Int32Asn1, {"tag_type": EXPLICIT, "tag": 0}),
        (KRB_ERROR_MSG_TYPE, Int32Asn1, {"tag_type": EXPLICIT, "tag": 1}),
        (
            KRB_ERROR_CTIME,
            KerberosTimeAsn1,
            {"tag_type": EXPLICIT, "tag": 2, "optional": True},
        ),
        (
            KRB_ERROR_CUSEC,
            Int32Asn1,
            {"tag_type": EXPLICIT, "tag": 3, "optional": True},
        ),
        (KRB_ERROR_STIME, KerberosTimeAsn1, {"tag_type": EXPLICIT, "tag": 4}),
        (KRB_ERROR_SUSEC, Int32Asn1, {"tag_type": EXPLICIT, "tag": 5}),
        (KRB_ERROR_ERROR_CODE, Int32Asn1, {"tag_type": EXPLICIT, "tag": 6}),
        (
            KRB_ERROR_CREALM,
            RealmAsn1,
            {"tag_type": EXPLICIT, "tag": 7, "optional": True},
        ),
        (
            KRB_ERROR_CNAME,
            PrincipalNameAsn1,
            {"tag_type": EXPLICIT, "tag": 8, "optional": True},
        ),
        (KRB_ERROR_REALM, RealmAsn1, {"tag_type": EXPLICIT, "tag": 9}),
        (KRB_ERROR_SNAME, PrincipalNameAsn1, {"tag_type": EXPLICIT, "tag": 10}),
        (
            KRB_ERROR_E_TEXT,
            core.GeneralString,
            {"tag_type": EXPLICIT, "tag": 11, "optional": True},
        ),
        (
            KRB_ERROR_E_DATA,
            core.OctetString,
            {"tag_type": EXPLICIT, "tag": 12, "optional": True},
        ),
    ]


# https://www.rfc-editor.org/rfc/rfc4120#section-5.4.2
# wrapped by ipapocket.krb5.objects.AsRep
class AsRepAsn1(KdcRepAsn1):
    """
    AS-REP          ::= [APPLICATION 11] KDC-REP
    """

    explicit = (APPLICATION, ApplicationTagNumbers.AS_REP.value)


# https://www.rfc-editor.org/rfc/rfc4120#section-5.4.2
class TgsRepAsn1(KdcRepAsn1):
    """
    TGS-REP         ::= [APPLICATION 13] KDC-REP
    """

    explicit = (APPLICATION, ApplicationTagNumbers.TGS_REP.value)


# class to handle different types of returned response
# wrapped by ipopacket.krb5.objects.KerberosResponse
class KerberosResponseAsn1(core.Choice):
    _alternatives = [
        (
            KERBEROS_RESPONSE_AS_REP,
            AsRepAsn1,
            {"implicit": (APPLICATION, MessageTypes.KRB_AS_REP.value)},
        ),
        (
            KERBEROS_RESPONSE_TGS_REP,
            TgsRepAsn1,
            {"implicit": (APPLICATION, MessageTypes.KRB_TGS_REP.value)},
        ),
        (
            KERBEROS_RESPONSE_KRB_ERROR,
            KrbErrorAsn1,
            {"implicit": (APPLICATION, MessageTypes.KRB_ERROR.value)},
        ),
    ]


# https://www.rfc-editor.org/rfc/rfc4120#appendix-A
# wrapped by ipapocket.krb5.objects.EtypeInfoEntry
class EtypeInfoEntryAsn1(core.Sequence):
    """
    ETYPE-INFO-ENTRY        ::= SEQUENCE {
        etype           [0] Int32,
        salt            [1] OCTET STRING OPTIONAL
    }
    """

    _fields = [
        (ETYPE_INFO_ETYPE, Int32Asn1, {"tag_type": EXPLICIT, "tag": 0}),
        (
            ETYPE_INFO_SALT,
            core.OctetString,
            {"tag_type": EXPLICIT, "tag": 1, "optional": True},
        ),
    ]


# https://www.rfc-editor.org/rfc/rfc4120#appendix-A
# wrapped by ipapocket.krb5.objects.EtypeInfo
class EtypeInfoAsn1(core.SequenceOf):
    """
    ETYPE-INFO              ::= SEQUENCE OF ETYPE-INFO-ENTRY
    """

    _child_spec = EtypeInfoEntryAsn1


# https://www.rfc-editor.org/rfc/rfc4120#appendix-A
# wrapped by ipapocket.krb5.objects.EtypeInfo2Entry
class EtypeInfo2EntryAsn1(core.Sequence):
    """
    ETYPE-INFO2-ENTRY       ::= SEQUENCE {
        etype           [0] Int32,
        salt            [1] KerberosString OPTIONAL,
        s2kparams       [2] OCTET STRING OPTIONAL
    }
    """

    _fields = [
        (ETYPE_INFO2_ETYPE, Int32Asn1, {"tag_type": EXPLICIT, "tag": 0}),
        (
            ETYPE_INFO2_SALT,
            KerberosStringAsn1,
            {"tag_type": EXPLICIT, "tag": 1, "optional": True},
        ),
        (
            ETYPE_INFO2_S2KPARAMS,
            core.OctetString,
            {"tag_type": EXPLICIT, "tag": 2, "optional": True},
        ),
    ]


# https://www.rfc-editor.org/rfc/rfc4120#appendix-A
# wrapped by ipapocket.krb5.objects.EtypeInfo2
class EtypeInfo2Asn1(core.SequenceOf):
    """
    ETYPE-INFO2             ::= SEQUENCE SIZE (1..MAX) OF ETYPE-INFO2-ENTRY
    """

    _child_spec = EtypeInfo2EntryAsn1


# https://www.rfc-editor.org/rfc/rfc4120#appendix-A
# wrapped by ipapocket.krb5.objects.PaEncTsEnc
class PaEncTsEncAsn1(core.Sequence):
    """
    PA-ENC-TS-ENC           ::= SEQUENCE {
        patimestamp     [0] KerberosTime -- client's time --,
        pausec          [1] Microseconds OPTIONAL
    }
    """

    _fields = [
        (
            PA_ENC_TS_ENC_PA_TIMESTAMP,
            KerberosTimeAsn1,
            {"tag_type": EXPLICIT, "tag": 0},
        ),
        (
            PA_ENC_TS_ENC_PA_USEC,
            MicrosecondsAsn1,
            {"tag_type": EXPLICIT, "tag": 1, "optional": True},
        ),
    ]


# https://www.rfc-editor.org/rfc/rfc4120#appendix-A
# wrapped by ipapocket.krb5.objects.EncAsRepPart
class EncAsRepPartAsn1(EncKdcRepPartAsn1):
    explicit = (APPLICATION, ApplicationTagNumbers.ENC_AS_REP_PART.value)


# https://www.rfc-editor.org/rfc/rfc4120#appendix-A
# wrapped by ipapocket.krb5.objects.EncTgsRepPart
class EncTgsRepPartAsn1(EncKdcRepPartAsn1):
    explicit = (APPLICATION, ApplicationTagNumbers.ENC_TGS_REP_PART.value)


# class to handle different type of response's encrypted part
# wrapped by ipapocket.krb5.objects.EncRepPart
class EncRepPartAsn1(core.Choice):
    _alternatives = [
        (
            ENC_PART_REP_AS_REP,
            EncAsRepPartAsn1,
            {"implicit": (APPLICATION, ApplicationTagNumbers.ENC_AS_REP_PART.value)},
        ),
        (
            ENC_PART_REP_TGS_REP,
            EncTgsRepPartAsn1,
            {"implicit": (APPLICATION, ApplicationTagNumbers.ENC_TGS_REP_PART.value)},
        ),
    ]
