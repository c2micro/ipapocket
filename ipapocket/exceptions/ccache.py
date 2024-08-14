class UnsupportedCcacheVersion(Exception):
    def __init__(self, version):
        super(Exception, self).__init__(
            "unsupported CCACHE version {}".format(hex(version))
        )
