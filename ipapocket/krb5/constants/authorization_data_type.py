import enum


# https://www.rfc-editor.org/rfc/rfc4120#section-7.5.4
class AuthorizationDataType(enum.Enum):
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
