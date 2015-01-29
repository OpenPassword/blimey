import os
import sys
import plistlib
from jinja2 import Template
from base64 import b64encode
from xml.parsers.expat import ExpatError

from blimey.agile_keychain._key import EncryptedKey
from blimey.exceptions import KeyAlreadyExistsForLevelException, InvalidKeyFileException

DEFAULT_ITERATIONS = 25000

# plistlib loading method name changed in Python 3.4.0, but the signature
# remained the same, so simply refer to the old method by new name in older
# Python versions
if sys.version_info < (3, 4, 0):
    plistlib.loads = plistlib.readPlistFromBytes

# In python 3.4 plistlib wraps the generic ExpatError in an exception of its own.
# Accept either to ensure Python 3.3 compatibility
if hasattr(plistlib, "InvalidFileException"):
    PLIST_EXCEPTIONS = (ExpatError, plistlib.InvalidFileException)
else:
    PLIST_EXCEPTIONS = ExpatError


class KeyManager:
    def __init__(self, path):
        self._base_path = path
        self._keys_file_path = os.path.join(self._base_path, 'data', 'default', '1password.keys')

    def get_keys(self):
        return self._read_keys_from_keys_plist()

    def save_key(self, new_key):
        keys = []

        for old_key in self._read_keys_from_keys_plist():
            if old_key.identifier == new_key.identifier:
                continue

            if old_key.level == new_key.level:
                raise KeyAlreadyExistsForLevelException()

            keys.append(old_key)

        keys.append(new_key)
        self._render_keys(keys)

    def _read_keys_from_keys_plist(self):
        plist_contents = self._load_keys_plist()

        if len(plist_contents) == 0:
            return []

        keys = self._parse_plist(plist_contents)

        return [EncryptedKey(key) for key in keys['list']]

    def _load_keys_plist(self):
        if os.path.exists(self._keys_file_path) is False:
            return None

        with open(self._keys_file_path, 'rb') as file:
            data = file.read()

        return self._remove_null_bytes(data)

    def _parse_plist(self, plist_contents):
        try:
            return plistlib.loads(plist_contents)
        except PLIST_EXCEPTIONS:
            raise InvalidKeyFileException

    def _remove_null_bytes(self, data):
        result = b''
        last = 0

        index = data.find(b'\x00')
        while index != -1:
            result = result + data[last:index]
            last = index + 1
            index = data.find(b'\x00', last)

        result = result + data[last:]

        return result

    def _render_keys(self, keys):
        template = self._load_template()
        keys = [self._serialize_key(key) for key in keys]

        with open(self._keys_file_path, 'w') as file:
            file.write(template.render({'keys': keys}))

    def _load_template(self):
        template_path = self._get_key_plist_template_path()

        with open(template_path, 'r') as file:
            return Template(file.read())

    def _serialize_key(self, key):
        return {
            'identifier': key.identifier,
            'iterations': key.iterations,
            'data': (b64encode(key.data) + b'\x00').decode('ascii'),
            'validation': (b64encode(key.validation) + b'\x00').decode('ascii'),
            'level': key.level
        }

    def _get_key_plist_template_path(self):
        return os.path.join(os.path.dirname(__file__), '..', 'template', '1password.keys.template')
