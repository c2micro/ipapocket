import enum


# https://github.com/freeipa/freeipa/blob/master/util/ipa_krb5.h#L90
class KdbSaltType(enum.Enum):
    NO_SALT = -1
    NORMAL = 0
    V4 = 1
    NOREALM = 2
    ONLYREALM = 3
    SPECIAL = 4
    AFS3 = 5
