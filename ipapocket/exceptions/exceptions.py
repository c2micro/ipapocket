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
