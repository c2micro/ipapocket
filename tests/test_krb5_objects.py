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
        self.assertEqual(Int32(MIN_INT32).value, MIN_INT32)
        with self.assertRaises(InvalidInt32Value):
            Int32(MIN_INT32 - 1)

    def test_max_value(self):
        self.assertEqual(Int32(MAX_INT32).value, MAX_INT32)
        with self.assertRaises(InvalidInt32Value):
            Int32(MAX_INT32 + 1)


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
        self.assertEqual(Int32(MIN_UINT32).value, MIN_UINT32)
        with self.assertRaises(InvalidUInt32Value):
            UInt32(MIN_UINT32 - 1)

    def test_max_value(self):
        self.assertEqual(UInt32(MAX_UINT32).value, MAX_UINT32)
        with self.assertRaises(InvalidUInt32Value):
            UInt32(MAX_UINT32 + 1)


class TestMicrosecondsObject(unittest.TestCase):
    def test_none_value(self):
        self.assertEqual(Microseconds().value, 0)

    def test_int_value(self):
        self.assertEqual(Microseconds(1).value, 1)
        self.assertEqual(Microseconds(0).value, 0)

    def test_microseconds_value(self):
        self.assertEqual(Microseconds(Microseconds(228)).value, 228)

    def test_min_value(self):
        self.assertEqual(Microseconds(MIN_MICROSECONDS).value, MIN_MICROSECONDS)
        with self.assertRaises(InvalidMicrosecondsValue):
            Microseconds(MIN_MICROSECONDS - 1)

    def test_max_value(self):
        self.assertEqual(Microseconds(MAX_MICROSECONDS).value, MAX_MICROSECONDS)
        with self.assertRaises(InvalidMicrosecondsValue):
            Microseconds(MAX_MICROSECONDS + 1)


if __name__ == "__main__":
    unittest.main()
