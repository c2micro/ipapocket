class InvalidPrincipalSyntax(Exception):
    def __init__(self, value):
        super(Exception, self).__init__("Invalid principal {}".format(value))
