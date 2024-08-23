import unittest
from ipapocket.krb5.types import *
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

# test PrincipalName
from tests.krb5.principal_name import TestPrincipalNameObject

# test Realm
from tests.krb5.realm import TestRealmObject

if __name__ == "__main__":
    unittest.main()
