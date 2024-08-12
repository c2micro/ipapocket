class InvalidPrincipalSyntax(Exception):
    def __init__(self, value):
        super(Exception, self).__init__("Invalid principal {}".format(value))


class InvalidInt32Value(Exception):
    def __init__(self, value: int):
        super(Exception, self).__init__(
            "Invalid Int32 value {} ({}). Must be in range -2147483648:2147483647".format(
                value,
                type(value).__name__,
            )
        )


class InvalidUInt32Value(Exception):
    def __init__(self, value: int):
        super(Exception, self).__init__(
            "Invalid UInt32 value {} ({}). Must be in range 0:4294967295".format(
                value,
                type(value).__name__,
            )
        )


class InvalidMicrosecondsValue(Exception):
    def __init__(self, value: int):
        super(Exception, self).__init__(
            "Invalid Microseconds value {} ({}). Must be in range 0:999999".format(
                value, type(value).__name__
            )
        )


class InvalidKerberosStringValue(Exception):
    def __init__(self, value):
        super(Exception, self).__init__(
            "Invalid KerberosString value {} ({})".format(value, type(value).__name__)
        )


class InvalidKerberosStringsValue(Exception):
    def __init__(self, value):
        super(Exception, self).__init__(
            "Invalid KerberosStrings value {} ({})".format(value, type(value).__name__)
        )


class InvalidRealmValue(Exception):
    def __init__(self, value):
        super(Exception, self).__init__(
            "Invalid Realm value {} ({})".format(value, type(value).__name__)
        )


class InvalidKerberosFlagsValueType(Exception):
    def __init__(self, value):
        super(Exception, self).__init__(
            "Invalid KerberosFlags value type {}, must be enum".format(
                type(value).__name__
            )
        )


class InvalidKdcOptionsValueType(Exception):
    def __init__(self, value):
        super(Exception, self).__init__(
            "Invalid KdcOptions value type {}".format(type(value).__name__)
        )


class InvalidTicketFlagsValueType(Exception):
    def __init__(self, value):
        super(Exception, self).__init__(
            "Invalid TicketFlags value type {}".format(type(value).__name__)
        )


class InvalidKerberosTimeValueType(Exception):
    def __init__(self, value):
        super(Exception, self).__init__(
            "Invalid KerberosTime value type {}".format(type(value).__name__)
        )


class InvalidEncTypesValueType(Exception):
    def __init__(self, value):
        super(Exception, self).__init__(
            "Invalid EncTypes value type {}".format(type(value).__name__)
        )


class InvalidTypeInKdcReqBody(Exception):
    def __init__(self, field, value):
        super(Exception, self).__init__(
            "Invalid type of value for {} field - {}".format(
                field, type(value).__name__
            )
        )


class InvalidTypeInKdcReq(Exception):
    def __init__(self, field, value):
        super(Exception, self).__init__(
            "Invalid type of value for {} field - {}".format(
                field, type(value).__name__
            )
        )


class InvalidPaDataValueType(Exception):
    pass


class InvalidPaDataType(Exception):
    pass


class InvalidAsReqRequest(Exception):
    pass


class InvalidPaEncTsEncPatimestamp(Exception):
    pass


class InvalidPaEncTsEncPausec(Exception):
    pass


class UnexpectedResponseType(Exception):
    def __init__(self, type):
        super(Exception, self).__init__("Unexpected response type {}".format(type))


class UnexpectedEncRepPartType(Exception):
    pass


class InvalidPrincipalNameType(Exception):
    def __init__(self, value):
        super(Exception, self).__init__(
            "Invalid type {} of PrincipalName".format(type(value).__name__)
        )
