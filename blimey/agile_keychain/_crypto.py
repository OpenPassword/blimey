import os
from pbkdf2 import PBKDF2
from Crypto.Cipher import AES
from Crypto.Hash import MD5
from base64 import b64encode, b64decode
from math import fmod
import json

from blimey.exceptions import IncorrectPasswordException
from blimey.agile_keychain._key import EncryptedKey, DecryptedKey
from blimey.agile_keychain.agile_keychain_item import EncryptedAgileKeychainItem, AgileKeychainItem


def generate_id():
    return MD5.new(os.urandom(32)).hexdigest().upper()


def decrypt_key(encrypted_key, password):
    password_key_iv = _derive_key_from_password(encrypted_key, password)
    master_key = _aes_decrypt(password_key_iv[0:16], password_key_iv[16:], encrypted_key.data[16:])

    validation_key_iv = _derive_validation_key(encrypted_key, master_key)
    validation_key = _aes_decrypt(validation_key_iv[0:16], validation_key_iv[16:], encrypted_key.validation[16:])

    if master_key != validation_key:
        raise IncorrectPasswordException()

    return DecryptedKey({
        'identifier': encrypted_key.identifier,
        'level': encrypted_key.level,
        'iterations': encrypted_key.iterations,
        'key': master_key
    })


def encrypt_key(decrypted_key, password, iterations=None):
    if iterations is None:
        iterations = decrypted_key.iterations

    master_salt = os.urandom(8)
    master_key = decrypted_key.key

    master_key_iv = PBKDF2(password, master_salt, iterations).read(32)
    encrypted_master_key = _aes_encrypt(master_key_iv[0:16], master_key_iv[16:], master_key)

    validation_salt = os.urandom(8)
    validation_key_iv = _derive_openssl_key(master_key, validation_salt)
    encrypted_validation_key = _aes_encrypt(validation_key_iv[0:16], validation_key_iv[16:], master_key)

    master_key = b'Salted__' + master_salt + encrypted_master_key
    validation_key = b'Salted__' + validation_salt + encrypted_validation_key

    return EncryptedKey({
        'identifier': decrypted_key.identifier,
        'level': decrypted_key.level,
        'iterations': iterations,
        'data': (b64encode(master_key) + b'\x00').decode('ascii'),
        'validation': (b64encode(validation_key) + b'\x00').decode('ascii')
    })


def create_key(password, level, iterations):
    master_salt = os.urandom(8)
    master_key = os.urandom(1024)

    master_key_iv = PBKDF2(password, master_salt, iterations).read(32)
    encrypted_master_key = _aes_encrypt(master_key_iv[0:16], master_key_iv[16:], master_key)

    validation_salt = os.urandom(8)
    validation_key_iv = _derive_openssl_key(master_key, validation_salt)
    encrypted_validation_key = _aes_encrypt(validation_key_iv[0:16], validation_key_iv[16:], master_key)

    master_key = b'Salted__' + master_salt + encrypted_master_key
    validation_key = b'Salted__' + validation_salt + encrypted_validation_key

    return EncryptedKey({
        'identifier': generate_id(),
        'level': level,
        'iterations': iterations,
        'data': (b64encode(master_key) + b'\x00').decode('ascii'),
        'validation': (b64encode(validation_key) + b'\x00').decode('ascii')
    })


def decrypt_item(item, decrypted_key):
    encrypted = b64decode(item['encrypted'])
    init_vector = encrypted[8:16]
    derived_key = _derive_openssl_key(decrypted_key.key, init_vector)
    decrypted = _aes_decrypt(derived_key[0:16], derived_key[16:], encrypted[16:])
    decrypted = strip_byte_padding(decrypted)
    decrypted_data = json.loads(decrypted.decode('utf8'))

    decrypted_item = AgileKeychainItem(item)
    decrypted_item['encrypted'] = decrypted_data

    return decrypted_item


def encrypt_item(item, decrypted_key):
    init_vector = os.urandom(8)
    derived_key = _derive_openssl_key(decrypted_key.key, init_vector)

    data = json.dumps(item['encrypted'])
    data = byte_pad(data.encode('utf8'), 16)
    data = _aes_encrypt(derived_key[0:16], derived_key[16:], data)

    encrypted_data = b64encode(b'Salted__' + init_vector + data).decode('ascii')

    encrypted_item = EncryptedAgileKeychainItem(item)
    encrypted_item['encrypted'] = encrypted_data

    return encrypted_item


def _derive_key_from_password(key, password):
    return PBKDF2(password, key.data[8:16], key.iterations).read(32)


def _derive_validation_key(key, encryption_key):
    return _derive_openssl_key(encryption_key, key.validation[8:16])


def _derive_openssl_key(key, salt):
    key = key[0:-16]
    openssl_key = bytes()
    prev = bytes()
    while len(openssl_key) < 32:
        prev = MD5.new(prev + key + salt).digest()
        openssl_key += prev

    return openssl_key


def _aes_encrypt(key, init_vector, data):
    return AES.new(key, AES.MODE_CBC, init_vector).encrypt(data)


def _aes_decrypt(key, init_vector, data):
    return AES.new(key, AES.MODE_CBC, init_vector).decrypt(data)


def byte_pad(input_bytes, length=16):
    if length > 256:
        raise ValueError("Maximum padding length is 256")

    # Modulo input bytes length with padding length to see how many bytes to pad with
    bytes_to_pad = length - int(fmod(len(input_bytes), length))

    if bytes_to_pad == length:
        bytes_to_pad = 0

    # Pad input bytes with a sequence of bytes containing the number of padded bytes
    input_bytes += bytes([bytes_to_pad] * bytes_to_pad)

    return input_bytes


def strip_byte_padding(input_bytes, length=16):
    if fmod(len(input_bytes), length) != 0:
        raise ValueError("Input byte length is not divisible by %s " % length)

    if input_bytes == b'':
        return input_bytes

    last_byte_value = ord(input_bytes[-1:].decode())

    if last_byte_value > length:
        return input_bytes

    if list(set(input_bytes[-last_byte_value:])) == [last_byte_value]:
        return input_bytes[0:-last_byte_value]

    raise ValueError("Invalid padding")
