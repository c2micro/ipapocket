import unittest
import sys

# hack to import from ipapocket
sys.path.append(".")

from ipapocket.krb5.objects import *
from ipapocket.krb5.constants import *
from ipapocket.exceptions.krb5 import *


class TestInt32Object(unittest.TestCase):
    def test_none_value(self):
        self.assertEqual(Int32().value, 0)

    def test_int_value(self):
        self.assertEqual(Int32(1).value, 1)
        self.assertEqual(Int32(-1231).value, -1231)

    def test_int32_value(self):
        self.assertEqual(Int32(Int32(228)).value, 228)

    def test_enum_value(self):
        self.assertEqual(
            Int32(MessageTypes.KRB_AP_REP).value, MessageTypes.KRB_AP_REP.value
        )

    def test_min_value(self):
        self.assertEqual(Int32(-2147483648).value, -2147483648)
        with self.assertRaises(InvalidInt32Value):
            Int32(-2147483649)

    def test_max_value(self):
        self.assertEqual(Int32(2147483647).value, 2147483647)
        with self.assertRaises(InvalidInt32Value):
            Int32(2147483648)


class TestUInt32Object(unittest.TestCase):
    def test_none_value(self):
        self.assertEqual(UInt32().value, 0)

    def test_int_value(self):
        self.assertEqual(UInt32(1).value, 1)
        self.assertEqual(UInt32(0).value, 0)

    def test_uint32_value(self):
        self.assertEqual(UInt32(UInt32(228)).value, 228)

    def test_enum_value(self):
        self.assertEqual(
            UInt32(MessageTypes.KRB_AP_REP).value, MessageTypes.KRB_AP_REP.value
        )

    def test_min_value(self):
        self.assertEqual(Int32(0).value, 0)
        with self.assertRaises(InvalidUInt32Value):
            UInt32(-1)

    def test_max_value(self):
        self.assertEqual(UInt32(4294967295).value, 4294967295)
        with self.assertRaises(InvalidUInt32Value):
            UInt32(4294967296)


class TestMicrosecondsObject(unittest.TestCase):
    def test_none_value(self):
        self.assertEqual(Microseconds().value, 0)

    def test_int_value(self):
        self.assertEqual(Microseconds(1).value, 1)
        self.assertEqual(Microseconds(0).value, 0)

    def test_microseconds_value(self):
        self.assertEqual(Microseconds(Microseconds(228)).value, 228)

    def test_min_value(self):
        self.assertEqual(Microseconds(0).value, 0)
        with self.assertRaises(InvalidMicrosecondsValue):
            Microseconds(-1)

    def test_max_value(self):
        self.assertEqual(Microseconds(999999).value, 999999)
        with self.assertRaises(InvalidMicrosecondsValue):
            Microseconds(1000000)


if __name__ == "__main__":
    unittest.main()
