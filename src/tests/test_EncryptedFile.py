from unittest import TestCase
import keyring
import keyrings
from keyrings.efile import EncryptedFile


class TestEncryptedFile(TestCase):

    def tearDown(self):
        self.ef.delete_password('a','b')

    def setUp(self) -> None:
        self.ef = EncryptedFile()
        self.ef.set_password('a', 'b', 'c')


    def test_get_password(self):
        self.assertEqual(self.ef.get_password('a','b'),'c')

    def test_print(self):
        kr = keyring.get_keyring()
        print(kr)

