import os
import json

from openpassword import abstract
from openpassword.exceptions import KeyValidationException, IncorrectPasswordException
from openpassword.agile_keychain._key_manager import KeyManager

AGILE_KEYCHAIN_BASE_FILES = ['1password.keys', 'contents.js', 'encryptionKeys.js']
DEFAULT_ITERATIONS = 25000


class DataSource(abstract.DataSource):
    BUILD_NUMBER_FILE = 'buildnum'
    BUILD_NUMBER = '32009'

    def __init__(self, path, key_manager=KeyManager):
        self._base_path = path
        self._default_folder = os.path.join(self._base_path, "data", "default")
        self._config_folder = os.path.join(self._base_path, "config")
        self._key_manager = key_manager(self._base_path)
        self._keys = []

    def create_buildnum_file(self):
        buildnum_file = os.path.join(self._config_folder, self.BUILD_NUMBER_FILE)
        buildnum_file = open(buildnum_file, "w+")
        buildnum_file.write(self.BUILD_NUMBER)
        buildnum_file.close()

    def initialise(self, password):
        os.makedirs(self._default_folder)
        os.makedirs(self._config_folder)

        self.create_buildnum_file()

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

    def authenticate(self, password):
        keys = self._key_manager.get_keys()

        for key in keys:
            try:
                key.decrypt_with_password(password)
            except KeyValidationException:
                raise IncorrectPasswordException

            self._keys.append(key)

    def set_password(self, password):
        for key in self._keys:
            key.encrypt_with_password(password)
            self._key_manager.save_key(key)

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

    def _initialise_key_files(self, password, iterations=DEFAULT_ITERATIONS):
        level3_key = self._key_manager.create_key(password, security_level='SL3', iterations=iterations)
        level5_key = self._key_manager.create_key(password, security_level='SL5', iterations=iterations)

        self._key_manager.save_key(level3_key)
        self._key_manager.save_key(level5_key)
