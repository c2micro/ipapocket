import enum


# https://www.rfc-editor.org/rfc/rfc4120#section-5.10
class ApplicationTagNumber(enum.Enum):
    TICKET = 1
    AUTHENTICATOR = 2
    ENC_TICKET_PART = 3
    AS_REQ = 10
    AS_REP = 11
    TGS_REQ = 12
    TGS_REP = 13
    AP_REQ = 14
    AP_REP = 15
    KRB_SAFE = 20
    KRB_PRIV = 21
    KRB_CRED = 22
    ENC_AS_REP_PART = 25
    ENC_TGS_REP_PART = 26
    ENC_AP_REP_PART = 27
    ENC_KRB_PRIV_PART = 28
    ENC_KRB_CRED_PART = 29
    KRB_ERROR = 30
