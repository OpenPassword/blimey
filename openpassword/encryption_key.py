from pbkdf2 import PBKDF2
from Crypto.Cipher import AES
from Crypto.Hash import MD5
from base64 import b64decode


def derive_openssl_key(key, salt, hash=MD5):
    key = key[0:-16]
    openssl_key = bytes()
    prev = bytes()
    while len(openssl_key) < 32:
        prev = hash.new(prev + key + salt).digest()
        openssl_key += prev

    return openssl_key


class EncryptionKey:

    def __init__(self, key):
        self.data = b64decode(key["data"])
        self.validation = b64decode(key["validation"])
        self.iterations = key["iterations"]

    def decrypt(self, password):
        decrypted_key = None
        decryption_key = self._decrypt_encryption_key(password)
        validation_key = self._decrypt_validation_key(decryption_key)

        if decryption_key == validation_key:
            decrypted_key = decryption_key

        return (decrypted_key is not None, decrypted_key)

    def _decrypt_encryption_key(self, password):
        data_key = self._derive_password_key(password)
        return self._decrypt(self.data[16:], data_key)

    def _derive_password_key(self, password):
        kdf = PBKDF2(password, self.data[8:16], self.iterations)
        return kdf.read(32)

    def _decrypt_validation_key(self, decryption_key):
        validation_key = self._derive_validation_key(decryption_key)
        return self._decrypt(self.validation[16:], validation_key)

    def _derive_validation_key(self, decryption_key):
        return derive_openssl_key(decryption_key, self.validation[8:16])

    def _decrypt(self, data, key_iv):
        key = key_iv[0:16]
        iv = key_iv[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.decrypt(data)
