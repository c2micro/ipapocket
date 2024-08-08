import enum

# https://www.rfc-editor.org/rfc/rfc4120#section-7.5.2
class PreAuthenticationDataTypes(enum.Enum):
    PA_TGS_REQ = 1
    PA_ENC_TIMESTAMP = 2
    PA_PW_SALT = 3
    # [reserved]                  4
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
    # Reserved values = 9_63
    OSF_DCE = 64
    SESAME = 65
    AD_OSF_DCE_PKI_CERTID = 66
    AD_WIN2K_PAC = 128
    AD_ETYPE_NEGOTIATION = 129

# https://www.rfc-editor.org/rfc/rfc4120#section-7.5.5
class TransitedEncodingTypes(enum.Enum):
    DOMAIN_X500_COMPRESS = 1 # 

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

# https://www.rfc-editor.org/rfc/rfc4120#section-7.5.8
class NameTypes(enum.Enum):
    KRB_NT_UNKNOWN = 0 # Name type not known
    KRB_NT_PRINCIPAL = 1 # Just the name of the principal as in DCE, or for users
    KRB_NT_SRV_INST = 2 # Service and other unique instance (krbtgt)
    KRB_NT_SRV_HST = 3 # Service with host name as instance (telnet, rcommands)
    KRB_NT_SRV_XHST = 4 # Service with host as remaining components
    KRB_NT_UID = 5 # Unique ID
    KRB_NT_X500_PRINCIPAL = 6 # Encoded X.509 Distinguished name [RFC2253]
    KRB_NT_SMTP_NAME = 7 # Name in form of SMTP email name (e.g., user@example.com)
    KRB_NT_ENTERPRISE = 10 # Enterprise name; may be mapped to principal name

# https://www.rfc-editor.org/rfc/rfc4120#section-7.5.9
class ErrorCodes(enum.Enum):
    KDC_ERR_NONE = 0 # No error
    KDC_ERR_NAME_EXP = 1 # Client's entry in database has expired
    KDC_ERR_SERVICE_EXP = 2 # Server's entry in database has expired
    KDC_ERR_BAD_PVNO = 3 # Requested protocol version number not supported
    KDC_ERR_C_OLD_MAST_KVNO = 4 # Client's key encrypted in old master key
    KDC_ERR_S_OLD_MAST_KVNO = 5 # 's key encrypted in old master key
    KDC_ERR_C_PRINCIPAL_UNKNOWN = 6 # Client not found in Kerberos database
    KDC_ERR_S_PRINCIPAL_UNKNOWN = 7 # Server not found in Kerberos database
    KDC_ERR_PRINCIPAL_NOT_UNIQUE = 8 # Multiple principal entries in database
    KDC_ERR_NULL_KEY = 9 # The client or server has a null key
    KDC_ERR_CANNOT_POSTDATE = 10 # Ticket not eligible for postdating
    KDC_ERR_NEVER_VALID = 11 # Requested starttime is later than end time
    KDC_ERR_POLICY = 12 # KDC policy rejects request
    KDC_ERR_BADOPTION = 13 # KDC cannot accommodate requested option
    KDC_ERR_ETYPE_NOSUPP = 14 # KDC has no support for encryption type
    KDC_ERR_SUMTYPE_NOSUPP = 15 # KDC has no support for checksum type
    KDC_ERR_PADATA_TYPE_NOSUPP = 16 # KDC has no support for padata type
    KDC_ERR_TRTYPE_NOSUPP = 17 # KDC has no support for transited type
    KDC_ERR_CLIENT_REVOKED = 18 # Clients credentials have been revoked
    KDC_ERR_SERVICE_REVOKED = 19 # Credentials for server have been revoked
    KDC_ERR_TGT_REVOKED = 20 # TGT has been revoked
    KDC_ERR_CLIENT_NOTYET = 21 # Client not yet valid; try again later
    KDC_ERR_SERVICE_NOTYET = 22 # Server not yet valid; try again later
    KDC_ERR_KEY_EXPIRED = 23 # Password has expired; change password to reset
    KDC_ERR_PREAUTH_FAILED = 24 # Pre-authentication information was invalid
    KDC_ERR_PREAUTH_REQUIRED  = 25 # Additional pre-authentication required
    KDC_ERR_SERVER_NOMATCH = 26 # Requested server and ticket don't match
    KDC_ERR_MUST_USE_USER2USER = 27 # Server principal valid for user2user only
    KDC_ERR_PATH_NOT_ACCEPTED = 28 # KDC Policy rejects transited path
    KDC_ERR_SVC_UNAVAILABLE = 29 # A service is not available
    KRB_AP_ERR_BAD_INTEGRITY = 31 # Integrity check on decrypted field failed
    KRB_AP_ERR_TKT_EXPIRED = 32 #Ticket expired
    KRB_AP_ERR_TKT_NYV = 33 # Ticket not yet valid
    KRB_AP_ERR_REPEAT = 34 # Request is a replay
    KRB_AP_ERR_NOT_US = 35 # The ticket isn't for us
    KRB_AP_ERR_BADMATCH = 36 # Ticket and authenticator don't match
    KRB_AP_ERR_SKEW = 37 # Clock skew too great
    KRB_AP_ERR_BADADDR = 38 # Incorrect net address
    KRB_AP_ERR_BADVERSION = 39 # Protocol version mismatch
    KRB_AP_ERR_MSG_TYPE = 40 # Invalid msg type
    KRB_AP_ERR_MODIFIED = 41 # Message stream modified
    KRB_AP_ERR_BADORDER = 42 # Message out of order
    KRB_AP_ERR_BADKEYVER = 44 # Specified version of key is not available
    KRB_AP_ERR_NOKEY = 45 # Service key not available
    KRB_AP_ERR_MUT_FAIL = 46 # Mutual authentication failed
    KRB_AP_ERR_BADDIRECTION = 47 # Incorrect message direction
    KRB_AP_ERR_METHOD = 48 # Alternative authentication method required
    KRB_AP_ERR_BADSEQ = 49 # Incorrect sequence number in message
    KRB_AP_ERR_INAPP_CKSUM = 50 #  Inappropriate type of checksum in message
    KRB_AP_PATH_NOT_ACCEPTED = 51 # Policy rejects transited path
    KRB_ERR_RESPONSE_TOO_BIG = 52 # Response too big for UDP; retry with TCP
    KRB_ERR_GENERIC = 60 # Generic error (description in e-text)
    KRB_ERR_FIELD_TOOLONG = 61 # Field is too long for this implementation
    KDC_ERROR_CLIENT_NOT_TRUSTED = 62 # Reserved for PKINIT
    KDC_ERROR_KDC_NOT_TRUSTED = 63 # Reserved for PKINIT
    KDC_ERROR_INVALID_SIG = 64 # Reserved for PKINIT
    KDC_ERR_KEY_TOO_WEAK = 65 # Reserved for PKINIT
    KDC_ERR_CERTIFICATE_MISMATCH = 66 # Reserved for PKINIT
    KRB_AP_ERR_NO_TGT = 67 # No TGT available to validate USER-TO-USER
    KDC_ERR_WRONG_REALM  = 68 # Reserved for future use
    KRB_AP_ERR_USER_TO_USER_REQUIRED = 69 # Ticket must be for USER-TO-USER
    KDC_ERR_CANT_VERIFY_CERTIFICATE = 70 # Reserved for PKINIT
    KDC_ERR_INVALID_CERTIFICATE = 71 # Reserved for PKINIT
    KDC_ERR_REVOKED_CERTIFICATE = 72 # Reserved for PKINIT
    KDC_ERR_REVOCATION_STATUS_UNKNOWN = 73 # Reserved for PKINIT
    KDC_ERR_REVOCATION_STATUS_UNAVAILABLE = 74 # Reserved for PKINIT
    KDC_ERR_CLIENT_NAME_MISMATCH = 75 # Reserved for PKINIT
    KDC_ERR_KDC_NAME_MISMATCH = 76 # Reserved for PKINIT

# https://www.opencore.com/blog/2017/3/kerberos-encryption-types/
# https://web.mit.edu/kerberos/krb5-devel/doc/admin/enctypes.html
# https://www.freeipa.org/page/Releases/4.8.0#highlights-in-4-8-0 (using only AES types since 4.8.0)
# https://www.freeipa.org/page/Releases/4.8.2#enhancements (default AES 256/384 since 4.8.2)
# Only types, that are used in FreeIPA (without deprecated)
class EncryptionTypes(enum.Enum):
    DES3_CBC_SHA1 = 16 # Triple DES cbc mode with HMAC/sha1
    AES128_CTS_HMAC_SHA1_96 = 17 # AES-128 CTS mode with 96-bit SHA-1 HMAC (https://www.rfc-editor.org/rfc/rfc3962)
    AES256_CTS_HMAC_SHA1_96 = 18 # AES-256 CTS mode with 96-bit SHA-1 HMAC (https://www.rfc-editor.org/rfc/rfc3962)
    AES128_CTS_HMAC_SHA256_128 = 19 # AES-128 CTS mode with 128-bit SHA-256 HMAC (https://www.rfc-editor.org/rfc/rfc8009)
    AES256_CTS_HMAC_SHA384_192 = 20 # AES-256 CTS mode with 192-bit SHA-384 HMAC (https://www.rfc-editor.org/rfc/rfc8009)
    ARCFOUR_HMAC = 23 # ArcFour with HMAC/md5 (https://www.rfc-editor.org/rfc/rfc4757)
    CAMELLIA128_CTS_CMAC = 25 # Camellia-128 CTS mode with CMAC (https://www.rfc-editor.org/rfc/rfc6803.html)
    CAMELLIA256_CTS_CMAC = 26 # Camellia-256 CTS mode with CMAC (https://www.rfc-editor.org/rfc/rfc6803.html)

# https://github.com/krb5/krb5/blob/master/src/include/krb5/krb5.hin#L442
# Only types, that are used in FreeIPA (without unkeyed/deprecated)
class ChecksumTypes(enum.Enum):
    HMAC_SHA1_96_AES128 = 15 # https://www.rfc-editor.org/rfc/rfc3962
    HMAC_SHA1_96_AES256 = 16 # https://www.rfc-editor.org/rfc/rfc3962
    CMAC_CAMELLIA128 = 17 # https://www.rfc-editor.org/rfc/rfc6803.html
    CMAC_CAMELLIA256 = 18 # https://www.rfc-editor.org/rfc/rfc6803.html
    HMAC_SHA256_128_AES128 = 19 # https://www.rfc-editor.org/rfc/rfc8009
    HMAC_SHA384_192_AES256 = 20 # https://www.rfc-editor.org/rfc/rfc8009

# https://www.rfc-editor.org/rfc/rfc4120#section-5.4.1
# without reserved bits
class KdcOptions(enum.Enum):
    FORWARDABLE = 1
    FORWARDED = 2
    PROXIABLE = 3
    PROXY = 4
    ALLOW_POSTDATE = 5
    POSTDATED = 6
    RENEWABLE = 8
    OPT_HARDWARE_AUTH = 11
    CANONICALIZE = 15
    DISABLE_TRANSITED_CHECK = 26
    RENEWABLE_OK = 27
    ENC_TKT_IN_SKEY = 28
    RENEW = 30
    VALIDATE = 31
