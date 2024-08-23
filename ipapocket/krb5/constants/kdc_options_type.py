import enum


# https://www.rfc-editor.org/rfc/rfc4120#section-5.4.1
# https://github.com/krb5/krb5/blob/bcc0dda256b184f8d87a4587f3f3997770020c87/src/include/krb5/krb5.hin#L1611
# without reserved bits
class KdcOptionsType(enum.Enum):
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
