class Asn1ConstrainedViolation(Exception):
    """
    Constrained violation of ASN1 data type
    """

    pass


class UnexpectedKerberosError(Exception):
    """
    Unexpected kerberos error for flow
    """

    def __init__(self, error_code, error_text):
        super(Exception, self).__init__(
            "Kerberos error: %s (%s)" % (error_code, error_text)
        )


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


class UnknownChecksumType(Exception):
    def __init__(self, cksumtype):
        super(Exception, self).__init__(
            "Unknown checksum type {} for crypto".format(cksumtype)
        )


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


class UnknownEncPartType(Exception):
    """
    Unknown encrypted part type
    """

    def __init__(self, name: str):
        super(Exception, self).__init__(
            "Unknown encrypted part type {} of AS-REP".format(name)
        )
