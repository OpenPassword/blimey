import json
from openpassword.keychain_item import KeychainItem
from openpassword.exceptions import InvalidUuidException


class AgileKeychainRepository:

    def __init__(self, path):
        self.path = path

    def key_for_security_level(self, security_level):
        key_file_path = self._resolve_key_file_path()
        keys = self._load_json(key_file_path)

        identifier = keys[security_level]

        for key in keys["list"]:
            if key["identifier"] == identifier:
                return key

    def get_item_by_unique_id(self, unique_id):
        keychain_item_path = self._resolve_keychain_item_path(unique_id)
        keychain_item = self._load_json(keychain_item_path)

        return KeychainItem(keychain_item)

    def _resolve_key_file_path(self):
        return self.path + '/data/default/encryptionKeys.js'

    def _resolve_keychain_item_path(self, uuid):
        return self.path + '/data/default/%s.1password' % uuid

    def _load_json(self, path):
        try:
            file = open(path)
        except IOError:
            raise InvalidUuidException("Invalid path: %s" % path)

        data = json.load(file)
        file.close()

        return data
