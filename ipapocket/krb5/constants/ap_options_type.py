import enum


# https://www.rfc-editor.org/rfc/rfc4120#section-5.5.1
# withour reserved bits
class ApOptionsType(enum.Enum):
    USE_SESSION_KEY = 1
    MUTUAL_REQUIRED = 2
