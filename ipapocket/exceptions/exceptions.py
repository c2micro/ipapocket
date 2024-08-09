from ipapocket.krb5.constants import ErrorCodes


class Asn1ConstrainedViolation(Exception):
    """
    Constrained violation of ASN1 data type
    """

    pass


class UnexpectedKerberosError(Exception):
    """
    Unexpected kerberos error for flow
    """

    def __init__(self, krb_msg):
        self._krb_msg = krb_msg.native
        self._err_code = ErrorCodes(self._krb_msg["error-code"])
        super(Exception, self).__init__("Kerberos error: %s" % self._err_code.name)


class NoSupportedEtypes(Exception):
    """
    When client is not support etypes from FreeIPA server
    """

    pass


class UnknownEtype(Exception):
    """
    Searching for unknown etype
    """

    def __init__(self, etype: str):
        super(Exception, self).__init__("Unknown etype {} for crypto".format(etype))


class InvalidKeyLength(Exception):
    """
    Invalid length of key
    """

    def __init__(self, actual: int):
        super(Exception, self).__init__("Invalid key size {} bytes".format(actual))


class InvalidSeedSize(Exception):
    """
    Invalid seed size in crypto
    """

    def __init__(self, actual: int, needed: int):
        super(Exception, self).__init__(
            "Invalid seed size: expected {} bytes, got {} bytes".format(actual, needed)
        )


class InvalidChecksum(Exception):
    pass
