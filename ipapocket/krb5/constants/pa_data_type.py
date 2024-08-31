import enum

# https://www.rfc-editor.org/rfc/rfc4120#section-7.5.2
# https://github.com/krb5/krb5/blob/784c38f50e70a739400cdd3f2620bac2e2788e6c/src/include/krb5/krb5.hin#L1791
class PreAuthenticationDataType(enum.Enum):
    PA_TGS_REQ = 1
    PA_ENC_TIMESTAMP = 2
    PA_PW_SALT = 3
    PA_ENC_UNIX_TIME = 5  # (deprecated)
    PA_SANDIA_SECUREID = 6
    PA_SESAME = 7
    PA_OSF_DCE = 8
    PA_CYBERSAFE_SECUREID = 9
    PA_AFS3_SALT = 10
    PA_ETYPE_INFO = 11
    PA_SAM_CHALLENGE = 12  # (sam/otp)
    PA_SAM_RESPONSE = 13  # (sam/otp)
    PA_PK_AS_REQ_OLD = 14  # (pkinit)
    PA_PK_AS_REP_OLD = 15  # (pkinit)
    PA_PK_AS_REQ = 16  # (pkinit)
    PA_PK_AS_REP = 17  # (pkinit)
    PA_ETYPE_INFO2 = 19  # (replaces pa_etype_info)
    PA_USE_SPECIFIED_KVNO = 20
    PA_SAM_REDIRECT = 21  # (sam/otp)
    PA_GET_FROM_TYPED_DATA = 22  # (embedded in typed data)
    TD_PADATA = 22  # (embeds padata)
    PA_SAM_ETYPE_INFO = 23  # (sam/otp)
    PA_ALT_PRINC = 24
    PA_SAM_CHALLENGE2 = 30
    PA_SAM_RESPONSE2 = 31
    PA_EXTRA_TGT = 41  # Reserved extra TGT
    TD_PKINIT_CMS_CERTIFICATES = 101  # CertificateSet from CMS
    TD_KRB_PRINCIPAL = 102  # PrincipalName
    TD_KRB_REALM = 103  # Realm
    TD_TRUSTED_CERTIFIERS = 104  # from PKINIT
    TD_CERTIFICATE_INDEX = 105  # from PKINIT
    TD_APP_DEFINED_ERROR = 106  # application specific
    TD_REQ_NONCE = 107  # INTEGER
    TD_REQ_SEQ = 108  # INTEGER
    PA_PAC_REQUEST = 128
    FOR_USER = 129
    S4U_X509_USER = 130
    AS_CHECKSUM = 132
    PA_FX_COOKIE = 133  # https://www.rfc-editor.org/rfc/rfc6113.html#section-6.4
    PA_AUTHENTICATION_SET = (
        134  # https://www.rfc-editor.org/rfc/rfc6113.html#section-6.4
    )
    PA_AUTH_SET_SELECTED = (
        135  # https://www.rfc-editor.org/rfc/rfc6113.html#section-6.4
    )
    PA_FX_FAST = 136  # https://www.rfc-editor.org/rfc/rfc6113.html#section-6.4
    PA_FX_ERROR = 137  # https://www.rfc-editor.org/rfc/rfc6113.html#section-6.4
    PA_ENCRYPTED_CHALLENGE = (
        138  # https://www.rfc-editor.org/rfc/rfc6113.html#section-6.4
    )
    OTP_CHALLENGE = 141
    OTP_REQUEST = 142
    OTP_PIN_CHANGE = 144
    PKINIT_KX = 147
    REQ_ENC_PA_REP = 149
    AS_FRESHNESS = 150
    SPAKE_CHALLENGE = 151
    REDHAT_IDP_OAUTH2 = 152
    REDHAT_PASSKEY = 153
    PAC_OPTIONS = 167