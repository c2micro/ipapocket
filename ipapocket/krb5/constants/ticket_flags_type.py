import enum


# https://www.rfc-editor.org/rfc/rfc4120#section-5.3
# https://github.com/krb5/krb5/blob/bcc0dda256b184f8d87a4587f3f3997770020c87/src/include/krb5/krb5.hin#L1705
# https://www.rfc-editor.org/rfc/rfc6112#section-3
# without reserved bits
class TicketFlagsType(enum.Enum):
    FORWARDABLE = 1
    FORWARDED = 2
    PROXIABLE = 3
    PROXY = 4
    MAY_POSTDATE = 5
    POSTDATED = 6
    INVALID = 7
    RENEWABLE = 8
    INITIAL = 9
    PRE_AUTHENT = 10
    HW_AUTHENT = 11
    TRANSITED_POLICY_CHECKED = 12
    OS_AS_DELEGATED = 13
    ENC_PA_REP = 15
    ANONYMOUS = 16  # https://www.rfc-editor.org/rfc/rfc6112#section-1
