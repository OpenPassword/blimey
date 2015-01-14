import os
import json
from base64 import b64encode
from pbkdf2 import PBKDF2
from openpassword import abstract
from Crypto.Cipher import AES
from Crypto.Hash import MD5
from jinja2 import Template

AGILE_KEYCHAIN_BASE_FILES = ['1password.keys', 'contents.js', 'encryptionKeys.js']
DEFAULT_ITERATIONS = 25000


class DataSource(abstract.DataSource):
    def __init__(self, path):
        self.base_path = path
        self._default_folder = os.path.join(self.base_path, "data", "default")

    def initialise(self, password):
        os.makedirs(self._default_folder)

        for agile_keychain_base_file in AGILE_KEYCHAIN_BASE_FILES:
            open(os.path.join(self._default_folder, agile_keychain_base_file), "w+").close()

        self._initialise_key_files(password)

        self.set_password(password)

    def is_keychain_initialised(self):
        return self._validate_agile_keychain_base_files() and self._is_valid_folder(self._default_folder)

    def add_item(self, item):
        file_handle = open(os.path.join(self._default_folder, "{0}.1password".format(item['id'])), "w")
        json.dump(item, file_handle)
        file_handle.close()

    def verify_password(self, password):
        file_handle = open(os.path.join(self._default_folder, "encryptionKeys.js"), "r")
        password_found = False

        if password in file_handle.read():
            password_found = True

        file_handle.close()
        return password_found

    def set_password(self, password):
        file_handle = open(os.path.join(self._default_folder, "encryptionKeys.js"), "w")
        file_handle.write(password)
        file_handle.close()

    def _validate_agile_keychain_base_files(self):
        is_initialised = True
        for base_file in AGILE_KEYCHAIN_BASE_FILES:
            current_file = os.path.join(self._default_folder, base_file)
            is_initialised = is_initialised and self._is_valid_file(current_file)
        return is_initialised

    def _is_valid_file(self, file):
        return os.path.exists(file) and os.path.isfile(file)

    def _is_valid_folder(self, folder):
        return os.path.exists(folder) and os.path.isdir(folder)

    def _initialise_key_files(self, password):
        self._write_keys(self._generate_keys(password))

    def _generate_keys(self, password, iterations=DEFAULT_ITERATIONS):
        level3_id = Crypto.generate_id()
        level3_data, level3_validation = Crypto.generate_key(password, iterations)

        level5_id = Crypto.generate_id()
        level5_data, level5_validation = Crypto.generate_key(password, iterations)

        return {
            'SL3': level3_id,
            'SL5': level5_id,
            'list': [
                {
                    'identifier': level3_id,
                    'iterations': iterations,
                    'data': (b64encode(level3_data) + b'\x00').decode('ascii'),
                    'validation': (b64encode(level3_validation) + b'\x00').decode('ascii'),
                    'level': 'SL3'
                },
                {
                    'identifier': level5_id,
                    'iterations': iterations,
                    'data': (b64encode(level5_data) + b'\x00').decode('ascii'),
                    'validation': (b64encode(level5_validation) + b'\x00').decode('ascii'),
                    'level': 'SL5'
                }
            ]
        }

    def _write_keys(self, keys):
        template_path = os.path.join(os.path.dirname(__file__), '1password.keys.template')

        with open(template_path, 'r') as file:
            plist_template = Template(file.read())

        with open(os.path.join(self._default_folder, "1password.keys"), "w") as file:
            file.write(plist_template.render(keys))


class Crypto:
    @staticmethod
    def generate_id():
        return MD5.new(os.urandom(32)).hexdigest().upper()

    @staticmethod
    def generate_key(password, iterations):
        master_salt = os.urandom(8)
        master_key = os.urandom(1024)

        pbkdf = PBKDF2(password, master_salt, iterations)
        master_key_iv = pbkdf.read(32)
        encrypted_master_key = Crypto.encrypt(master_key_iv[0:16], master_key_iv[16:], master_key)

        validation_salt = os.urandom(8)
        validation_key_iv = Crypto.derive_key(master_key, validation_salt)
        encrypted_validation_key = Crypto.encrypt(validation_key_iv[0:16], validation_key_iv[16:], master_key)

        master = b'Salted__' + master_salt + encrypted_master_key
        validation = b'Salted__' + validation_salt + encrypted_validation_key

        return (master, validation)

    @staticmethod
    def encrypt(key, init_vector, data):
        cipher = AES.new(key, AES.MODE_CBC, init_vector)
        return cipher.encrypt(data)

    @staticmethod
    def derive_key(key, salt):
        key = key[0:-16]
        openssl_key = bytes()
        prev = bytes()
        while len(openssl_key) < 32:
            prev = MD5.new(prev + key + salt).digest()
            openssl_key += prev

        return openssl_key
