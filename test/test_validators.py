__author__ = 'Matt David'

from mock import patch, Mock, MagicMock
from test import AddressimoTestCase

from addressimo.validators import *

class TestIsValidString(AddressimoTestCase):

    def test_goright(self):

        # Test Empties
        self.assertFalse(is_valid_string(None))
        self.assertFalse(is_valid_string(''))

        # Valid Fields
        self.assertTrue(is_valid_string('billybob'))
        self.assertTrue(is_valid_string('billybo-.#(!b75'))

        # Invalid Fields
        self.assertFalse(is_valid_string('[45]vfgdf\\/'))
        self.assertFalse(is_valid_string('();'))
        self.assertFalse(is_valid_string('this@me.com$'))
        self.assertFalse(is_valid_string('`~>'))