import unittest
import sys

# hack to import from ipapocket
sys.path.append(".")

from ipapocket.krb5.objects import *
from ipapocket.krb5.constants import *
from ipapocket.exceptions.krb5 import *

# test Int32
from tests.krb5.int32 import TestInt32Object

# test UInt32
from tests.krb5.uint32 import TestUInt32Object

# test Microseconds
from tests.krb5.microseconds import TestMicrosecondsObject

# test KerberosString
from tests.krb5.kerberos_string import TestKerberosStringObject

# test KerberosStrings
from tests.krb5.kerberos_strings import TestKerberosStringsObject


if __name__ == "__main__":
    unittest.main()
