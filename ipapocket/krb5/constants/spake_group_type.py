import enum


# https://web.mit.edu/kerberos/krb5-devel/doc/admin/conf_files/krb5_conf.html
# https://github.com/krb5/krb5/blob/b9b654e5b469140d5603f27af5bf83ee9a826349/src/plugins/preauth/spake/iana.h#L43
class SpakeGroupType(enum.Enum):
    EDWARDS25519 = 1  # https://datatracker.ietf.org/doc/html/rfc7748.html
    P256 = 2  # https://datatracker.ietf.org/doc/html/rfc5480.html
    P384 = 3  # https://datatracker.ietf.org/doc/html/rfc5480.html
    P521 = 4  # https://datatracker.ietf.org/doc/html/rfc5480.html
