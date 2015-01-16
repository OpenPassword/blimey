import os
import shutil
from nose.tools import raises

from openpassword.agile_keychain import DataSource
from openpassword.exceptions import IncorrectPasswordException


class AgileKeychainDataSourceTest:
    _temporary_path = os.path.join('tests', 'fixtures', 'temp.agilekeychain')
    _password = "somepassword"
    _data_source = None

    def it_creates_agile_keychain_folder_structure_on_initialisation(self):
        self._initialise_data_source()
        self._check_keychain_dir()
        self._check_data_default_dir()
        self._check_config_dir()
        self._check_keys_file()
        self._check_contents_file()
        self._check_buildnum_file()
        self._check_encryption_keys_file()

    def it_authenticates_with_a_password(self):
        self._initialise_data_source()
        self._data_source.authenticate(self._password)

    @raises(IncorrectPasswordException)
    def it_fails_authentication_with_incorrect_password_exception(self):
        self._initialise_data_source()
        self._data_source.authenticate('wrongpassord')

    def it_is_created_initialised_with_path_to_existing_keychain(self):
        data_source = DataSource(os.path.join('tests', 'fixtures', 'test.agilekeychain'))
        assert data_source.is_keychain_initialised()

    def it_is_created_non_initialised_with_path_to_non_existing_keychain(self):
        data_source = DataSource("nonexistingfolder")
        assert data_source.is_keychain_initialised() is False

    def it_adds_new_items_to_the_keychain(self):
        data_source = DataSource(os.path.join('tests', 'fixtures', 'test.agilekeychain'))
        data_source.add_item({'id': '79cd94b00ab34d209d62e487e77965a5'})

        assert os.path.exists(os.path.join('tests', 'fixtures', 'test.agilekeychain', 'data', 'default',
                                           '79cd94b00ab34d209d62e487e77965a5.1password')) is True
        os.remove(os.path.join('tests', 'fixtures', 'test.agilekeychain', 'data', 'default',
                               '79cd94b00ab34d209d62e487e77965a5.1password'))

    def _initialise_data_source(self):
        self._data_source = DataSource(self._temporary_path)
        self._data_source.initialise(self._password)
        self.teardown = self._path_clean

    def _path_clean(self):
        shutil.rmtree(self._temporary_path)

    def _get_data_default_dir(self):
        return os.path.join(self._temporary_path, "data", "default")

    def _get_config_dir(self):
        return os.path.join(self._temporary_path, 'config')

    def _check_keychain_dir(self):
        assert self._exists_and_is_dir(self._temporary_path)

    def _check_data_default_dir(self):
        assert self._exists_and_is_dir(self._get_data_default_dir())

    def _check_config_dir(self):
        assert self._exists_and_is_dir(self._get_config_dir())

    def _check_keys_file(self):
        keys_file = os.path.join(self._get_data_default_dir(), '1password.keys')
        assert self._exists_and_is_file(keys_file)

    def _check_contents_file(self):
        contents_file = os.path.join(self._get_data_default_dir(), 'contents.js')
        assert self._exists_and_is_file(contents_file)

    def _check_buildnum_file(self):
        buildnum_file = os.path.join(self._get_config_dir(), 'buildnum')
        assert self._exists_and_is_file(buildnum_file)

    def _check_encryption_keys_file(self):
        encryption_keys_file = os.path.join(self._get_data_default_dir(), 'encryptionKeys.js')
        assert self._exists_and_is_file(encryption_keys_file)

    def _exists_and_is_file(self, path):
        return os.path.exists(path) and os.path.isfile(path)

    def _exists_and_is_dir(self, path):
        return os.path.exists(path) and os.path.isdir(path)
