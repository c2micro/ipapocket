import unittest
from ipapocket.krb5.types import *
from ipapocket.krb5.constants import *
from ipapocket.exceptions.krb5 import *


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

    def test_asn1_native(self):
        self.assertEqual(Microseconds(123).to_asn1().native, 123)

    def test_eq(self):
        self.assertEqual(Microseconds(9999), Microseconds(9999))
        self.assertEqual(Microseconds(9999), 9999)
