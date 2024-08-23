class InvalidPortNumber(Exception):
    def __init__(self, port_number):
        super(Exception, self).__init__(
            "Invalid port number {}, must be in range 1:65535".format(port_number)
        )

class InvalidPortType(Exception):
    def __init__(self, port):
        super(Exception, self).__init__(
            "Invalid port type {}, must be int".format(type(port).__name__)
        )
