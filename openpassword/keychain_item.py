import json
from base64 import b64decode
from openpassword.pkcs_utils import byte_pad, strip_byte_padding
from openpassword.openssl_utils import derive_openssl_key
from os import urandom
from openpassword.crypt_utils import *


class KeychainItem:
    def __init__(self, item):
        self.key_id = item["keyID"]
        self.encrypted = b64decode(item["encrypted"])
        self.data = None
        self.initialisation_vector = None

    def set_private_contents(self, data):
        self.encrypted = None
        self.data = data

    def _encrypt(self, original_key):
        data = json.dumps(self.data)
        data = byte_pad(data.encode('utf8'))
        data = encrypt(data, self._derive_key(original_key, self.initialisation_vector))
        return data

    def encrypt(self, original_key):
        self._generate_iv()
        encrypted_data = self._encrypt(original_key)

        self.encrypted = b''.join(
            ['Salted__'.encode('utf8'), self.initialisation_vector, encrypted_data])

    def decrypt(self, original_key):
        self._extract_iv()
        data = decrypt(self.encrypted[16:], self._derive_key(original_key, self.initialisation_vector))
        data = strip_byte_padding(data)

        self.data = json.loads(data.decode('utf8'))

    def _generate_iv(self):
        self.initialisation_vector = urandom(8)

    def _extract_iv(self):
        self.initialisation_vector = self.encrypted[8:16]

    def _derive_key(self, key, iv):
        return derive_openssl_key(key, iv)

    def _derive_decryption_key(self, decryption_key):
        return derive_openssl_key(decryption_key, self.encrypted[8:16])
