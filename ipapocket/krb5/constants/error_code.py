import enum


# https://www.rfc-editor.org/rfc/rfc4120#section-7.5.9
class ErrorCode(enum.Enum):
    KDC_ERR_NONE = 0  # No error
    KDC_ERR_NAME_EXP = 1  # Client's entry in database has expired
    KDC_ERR_SERVICE_EXP = 2  # Server's entry in database has expired
    KDC_ERR_BAD_PVNO = 3  # Requested protocol version number not supported
    KDC_ERR_C_OLD_MAST_KVNO = 4  # Client's key encrypted in old master key
    KDC_ERR_S_OLD_MAST_KVNO = 5  # 's key encrypted in old master key
    KDC_ERR_C_PRINCIPAL_UNKNOWN = 6  # Client not found in Kerberos database
    KDC_ERR_S_PRINCIPAL_UNKNOWN = 7  # Server not found in Kerberos database
    KDC_ERR_PRINCIPAL_NOT_UNIQUE = 8  # Multiple principal entries in database
    KDC_ERR_NULL_KEY = 9  # The client or server has a null key
    KDC_ERR_CANNOT_POSTDATE = 10  # Ticket not eligible for postdating
    KDC_ERR_NEVER_VALID = 11  # Requested starttime is later than end time
    KDC_ERR_POLICY = 12  # KDC policy rejects request
    KDC_ERR_BADOPTION = 13  # KDC cannot accommodate requested option
    KDC_ERR_ETYPE_NOSUPP = 14  # KDC has no support for encryption type
    KDC_ERR_SUMTYPE_NOSUPP = 15  # KDC has no support for checksum type
    KDC_ERR_PADATA_TYPE_NOSUPP = 16  # KDC has no support for padata type
    KDC_ERR_TRTYPE_NOSUPP = 17  # KDC has no support for transited type
    KDC_ERR_CLIENT_REVOKED = 18  # Clients credentials have been revoked
    KDC_ERR_SERVICE_REVOKED = 19  # Credentials for server have been revoked
    KDC_ERR_TGT_REVOKED = 20  # TGT has been revoked
    KDC_ERR_CLIENT_NOTYET = 21  # Client not yet valid; try again later
    KDC_ERR_SERVICE_NOTYET = 22  # Server not yet valid; try again later
    KDC_ERR_KEY_EXPIRED = 23  # Password has expired; change password to reset
    KDC_ERR_PREAUTH_FAILED = 24  # Pre-authentication information was invalid
    KDC_ERR_PREAUTH_REQUIRED = 25  # Additional pre-authentication required
    KDC_ERR_SERVER_NOMATCH = 26  # Requested server and ticket don't match
    KDC_ERR_MUST_USE_USER2USER = 27  # Server principal valid for user2user only
    KDC_ERR_PATH_NOT_ACCEPTED = 28  # KDC Policy rejects transited path
    KDC_ERR_SVC_UNAVAILABLE = 29  # A service is not available
    KRB_AP_ERR_BAD_INTEGRITY = 31  # Integrity check on decrypted field failed
    KRB_AP_ERR_TKT_EXPIRED = 32  # Ticket expired
    KRB_AP_ERR_TKT_NYV = 33  # Ticket not yet valid
    KRB_AP_ERR_REPEAT = 34  # Request is a replay
    KRB_AP_ERR_NOT_US = 35  # The ticket isn't for us
    KRB_AP_ERR_BADMATCH = 36  # Ticket and authenticator don't match
    KRB_AP_ERR_SKEW = 37  # Clock skew too great
    KRB_AP_ERR_BADADDR = 38  # Incorrect net address
    KRB_AP_ERR_BADVERSION = 39  # Protocol version mismatch
    KRB_AP_ERR_MSG_TYPE = 40  # Invalid msg type
    KRB_AP_ERR_MODIFIED = 41  # Message stream modified
    KRB_AP_ERR_BADORDER = 42  # Message out of order
    KRB_AP_ERR_BADKEYVER = 44  # Specified version of key is not available
    KRB_AP_ERR_NOKEY = 45  # Service key not available
    KRB_AP_ERR_MUT_FAIL = 46  # Mutual authentication failed
    KRB_AP_ERR_BADDIRECTION = 47  # Incorrect message direction
    KRB_AP_ERR_METHOD = 48  # Alternative authentication method required
    KRB_AP_ERR_BADSEQ = 49  # Incorrect sequence number in message
    KRB_AP_ERR_INAPP_CKSUM = 50  #  Inappropriate type of checksum in message
    KRB_AP_PATH_NOT_ACCEPTED = 51  # Policy rejects transited path
    KRB_ERR_RESPONSE_TOO_BIG = 52  # Response too big for UDP; retry with TCP
    KRB_ERR_GENERIC = 60  # Generic error (description in e-text)
    KRB_ERR_FIELD_TOOLONG = 61  # Field is too long for this implementation
    KDC_ERROR_CLIENT_NOT_TRUSTED = 62  # Reserved for PKINIT
    KDC_ERROR_KDC_NOT_TRUSTED = 63  # Reserved for PKINIT
    KDC_ERROR_INVALID_SIG = 64  # Reserved for PKINIT
    KDC_ERR_KEY_TOO_WEAK = 65  # Reserved for PKINIT
    KDC_ERR_CERTIFICATE_MISMATCH = 66  # Reserved for PKINIT
    KRB_AP_ERR_NO_TGT = 67  # No TGT available to validate USER-TO-USER
    KDC_ERR_WRONG_REALM = 68  # Reserved for future use
    KRB_AP_ERR_USER_TO_USER_REQUIRED = 69  # Ticket must be for USER-TO-USER
    KDC_ERR_CANT_VERIFY_CERTIFICATE = 70  # Reserved for PKINIT
    KDC_ERR_INVALID_CERTIFICATE = 71  # Reserved for PKINIT
    KDC_ERR_REVOKED_CERTIFICATE = 72  # Reserved for PKINIT
    KDC_ERR_REVOCATION_STATUS_UNKNOWN = 73  # Reserved for PKINIT
    KDC_ERR_REVOCATION_STATUS_UNAVAILABLE = 74  # Reserved for PKINIT
    KDC_ERR_CLIENT_NAME_MISMATCH = 75  # Reserved for PKINIT
    KDC_ERR_KDC_NAME_MISMATCH = 76  # Reserved for PKINIT
    KDC_ERR_PREAUTH_EXPIRED = (
        90  # https://www.rfc-editor.org/rfc/rfc6113.html#section-6.1
    )
    KDC_ERR_MORE_PREAUTH_DATA_REQUIRED = (
        91  # https://www.rfc-editor.org/rfc/rfc6113.html#section-6.1
    )
    KDC_ERR_PREAUTH_BAD_AUTHENTICATION_SET = (
        92  # https://www.rfc-editor.org/rfc/rfc6113.html#section-6.1
    )
    KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS = (
        93  # https://www.rfc-editor.org/rfc/rfc6113.html#section-6.1
    )
