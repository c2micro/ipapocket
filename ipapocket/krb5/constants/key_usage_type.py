import enum


# https://www.rfc-editor.org/rfc/rfc4120#section-7.5.1
# https://github.com/krb5/krb5/blob/bcc0dda256b184f8d87a4587f3f3997770020c87/src/include/krb5/krb5.hin#L935
class KeyUsageType(enum.Enum):
    MASTER_KEY = 0  # for encryption/decryption keyblocks using MK (https://github.com/krb5/krb5/blob/5495454583261ab5567b9916cbcfd41a3d5bd75d/src/lib/kdb/decrypt_key.c#L88)
    AS_REQ_PA_ENC_TIMESTAMP = 1
    KDC_REP_TICKET = 2
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
    KEY_USAGE_FAST_REQ_CHKSUM = (
        50  # https://www.rfc-editor.org/rfc/rfc6113.html#section-6.2
    )
    KEY_USAGE_FAST_ENC = 51  # https://www.rfc-editor.org/rfc/rfc6113.html#section-6.2
    KEY_USAGE_FAST_REP = 52  # https://www.rfc-editor.org/rfc/rfc6113.html#section-6.2
    KEY_USAGE_FAST_FINISHED = (
        53  # https://www.rfc-editor.org/rfc/rfc6113.html#section-6.2
    )
    KEY_USAGE_ENC_CHALLENGE_CLIENT = (
        54  # https://www.rfc-editor.org/rfc/rfc6113.html#section-6.2
    )
    KEY_USAGE_ENC_CHALLENGE_KDC = (
        55  # https://www.rfc-editor.org/rfc/rfc6113.html#section-6.2
    )
