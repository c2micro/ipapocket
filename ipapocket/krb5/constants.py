import enum

# https://www.rfc-editor.org/rfc/rfc4120#section-7.5.1
class KeyUsageTypes(enum.Enum):
    AS_REQ_PA_ENC_TIMESTAMP = 1
    AS_TGS_REP = 2
    AS_REP_ENCPART = 3
    TGS_REQ_AD_SESSKEY = 4
    TGS_REQ_AD_SUBKEY = 5
    TGS_REQ_AUTH_CKSUM = 6
    TGS_REQ_AUTH = 7
    TGS_REP_ENCPART_SESSKEY = 8
    TGS_REP_ENCPART_SUBKEY = 9
    AP_REQ_AUTH_CKSUM = 10
    AP_REQ_AUTH = 11
    AP_REP_ENCPART = 12
    KRB_PRIV_ENCPART = 13
    KRB_CRED_ENCPART = 14
    KRB_SAFE_CHKSUM = 15
    AD_KDC_ISSUED_CHKSUM = 19

# https://www.rfc-editor.org/rfc/rfc4120#section-7.5.2
class PreAuthenticationDataTypes(enum.Enum):
    PA_TGS_REQ = 1
    PA_ENC_TIMESTAMP = 2
    PA_PW_SALT = 3
    PA_ENC_UNIX_TIME = 5 # (deprecated)
    PA_SANDIA_SECUREID = 6
    PA_SESAME = 7
    PA_OSF_DCE = 8
    PA_CYBERSAFE_SECUREID = 9
    PA_AFS3_SALT = 10
    PA_ETYPE_INFO = 11
    PA_SAM_CHALLENGE = 12 # (sam/otp)
    PA_SAM_RESPONSE = 13 # (sam/otp)
    PA_PK_AS_REQ_OLD = 14 # (pkinit)
    PA_PK_AS_REP_OLD = 15 # (pkinit)
    PA_PK_AS_REQ = 16 # (pkinit)
    PA_PK_AS_REP = 17 # (pkinit)
    PA_ETYPE_INFO2 = 19 # (replaces pa_etype_info)
    PA_USE_SPECIFIED_KVNO = 20
    PA_SAM_REDIRECT = 21 # (sam/otp)
    PA_GET_FROM_TYPED_DATA = 22 # (embedded in typed data)
    TD_PADATA = 22 # (embeds padata)
    PA_SAM_ETYPE_INFO = 23 # (sam/otp)
    PA_ALT_PRINC = 24
    PA_SAM_CHALLENGE2 = 30
    PA_SAM_RESPONSE2 = 31
    PA_EXTRA_TGT = 41 # Reserved extra TGT
    TD_PKINIT_CMS_CERTIFICATES = 101 # CertificateSet from CMS
    TD_KRB_PRINCIPAL = 102 # PrincipalName
    TD_KRB_REALM = 103 # Realm
    TD_TRUSTED_CERTIFIERS = 104 # from PKINIT
    TD_CERTIFICATE_INDEX = 105 # from PKINIT
    TD_APP_DEFINED_ERROR = 106 # application specific
    TD_REQ_NONCE = 107 # INTEGER
    TD_REQ_SEQ = 108 # INTEGER
    PA_PAC_REQUEST = 128

# https://www.rfc-editor.org/rfc/rfc4120#section-7.5.3
class AddressTypes(enum.Enum):
    IPv4 = 2
    Directional = 3
    ChaosNet = 5
    XNS = 6
    ISO = 7
    DECNET_Phase_IV = 12
    AppleTalk_DDP = 16
    NetBios = 20
    IPv6 = 24

# https://www.rfc-editor.org/rfc/rfc4120#section-7.5.4
class AuthorizationDataTypes(enum.Enum):
    AD_IF_RELEVANT = 1
    AD_INTENDED_FOR_SERVER = 2
    AD_INTENDED_FOR_APPLICATION_CLASS = 3
    AD_KDC_ISSUED = 4
    AD_AND_OR = 5
    AD_MANDATORY_TICKET_EXTENSIONS = 6
    AD_IN_TICKET_EXTENSIONS = 7
    AD_MANDATORY_FOR_KDC = 8
    OSF_DCE = 64
    SESAME = 65
    AD_OSF_DCE_PKI_CERTID = 66
    AD_WIN2K_PAC = 128
    AD_ETYPE_NEGOTIATION = 129

# https://www.rfc-editor.org/rfc/rfc4120#section-7.5.5
class TransitedEncodingTypes(enum.Enum):
    DOMAIN_X500_COMPRESS = 1

# https://www.rfc-editor.org/rfc/rfc4120#section-7.5.6
class ProtocolVersionNumber(enum.Enum):
    pvno = 5 # Current Kerberos protocol version number

# https://www.rfc-editor.org/rfc/rfc4120#section-7.5.7
class MessageTypes(enum.Enum):
    KRB_AS_REQ = 10 # Request for initial authentication
    KRB_AS_REP = 11 # Response to KRB_AS_REQ request
    KRB_TGS_REQ = 12 # Request for authentication based on TGT
    KRB_TGS_REP = 13 # Response to KRB_TGS_REQ request
    KRB_AP_REQ = 14 # Application request to server
    KRB_AP_REP = 15 # Response to KRB_AP_REQ_MUTUAL
    KRB_RESERVED16 = 16 # Reserved for user-to-user krb_tgt_request
    KRB_RESERVED17 = 17 # Reserved for user-to-user krb_tgt_reply
    KRB_SAFE = 20 # Safe (checksummed) application message
    KRB_PRIV = 21 # Private (encrypted) application message
    KRB_CRED = 22 # Private (encrypted) message to forward credentials
    KRB_ERROR = 30 # Error response
