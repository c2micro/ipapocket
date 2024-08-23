import enum


# https://www.rfc-editor.org/rfc/rfc4120#section-7.5.8
# https://github.com/krb5/krb5/blob/b9b654e5b469140d5603f27af5bf83ee9a826349/src/include/krb5/krb5.hin#L232
class NameType(enum.Enum):
    NT_UNKNOWN = 0
    NT_PRINCIPAL = 1
    NT_SRV_INST = 2
    NT_SRV_HST = 3
    NT_SRV_XHST = 4
    NT_UID = 5
    NT_X500_PRINCIPAL = 6
    NT_SMTP_NAME = 7
    NT_ENTERPRISE_PRINCIPAL = 10
    NT_WELLKNOWN = 11
