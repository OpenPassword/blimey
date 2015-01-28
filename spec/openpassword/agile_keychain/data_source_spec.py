from unittest.mock import patch, Mock, MagicMock, call
from nose.tools import raises

from blimey.agile_keychain import DataSource
from blimey.exceptions import IncorrectPasswordException, UnauthenticatedDataSourceException, \
    ItemNotFoundException
from blimey.agile_keychain.agile_keychain_item import AgileKeychainItem
from blimey.agile_keychain._manager._file_system_manager import FileSystemManager
from blimey.agile_keychain._manager._key_manager import KeyManager
from blimey.agile_keychain._manager._item_manager import ItemManager
from blimey.agile_keychain._key import EncryptedKey


class DataSourceSpec:
    @patch('blimey.agile_keychain.data_source.FileSystemManager')
    @patch('blimey.agile_keychain.data_source.KeyManager')
    @patch('blimey.agile_keychain.data_source.ItemManager')
    def it_initialises_paths(self, item_manager, key_manager, file_system_manager):
        DataSource('some_path')

        file_system_manager.assert_called_once_with('some_path')
        key_manager.assert_called_once_with('some_path')
        item_manager.assert_called_once_with('some_path')

    @patch.object(KeyManager, 'save_key')
    @patch.object(FileSystemManager, 'initialise')
    def it_creates_file_system_and_keys_on_initialisation(self, initialise_file_system, save_key):
        data_source = DataSource('some_path')
        data_source.initialise('password', {'iterations': 2})

        initialise_file_system.assert_called_once_with()

        # I'm sure there's a better way to unpack these...
        first_key = save_key.call_args_list[0][0][0]
        second_key = save_key.call_args_list[1][0][0]

        assert type(first_key) is EncryptedKey
        assert first_key.level == 'SL3'
        assert first_key.iterations == 2

        assert type(second_key) is EncryptedKey
        assert second_key.level == 'SL5'
        assert first_key.iterations == 2

    @patch.object(FileSystemManager, 'is_initialised')
    def it_delegates_initialisation_check_to_file_system_manager(self, is_initialised):
        data_source = DataSource('some_path')
        is_initialised.return_value = True

        assert data_source.is_initialised() is True

    @patch("blimey.agile_keychain.data_source.crypto.decrypt_key")
    @patch.object(KeyManager, 'get_keys')
    def it_authenticates_against_all_keys(self, get_keys, decrypt_key):
        key3 = Mock()
        key5 = Mock()
        get_keys.return_value = [key3, key5]

        data_source = DataSource('some_path')
        data_source.authenticate('password')

        decrypt_key.assert_has_calls([call(key3, 'password'), call(key5, 'password')])
        assert data_source.is_authenticated() is True

    @patch("blimey.agile_keychain.data_source.crypto.decrypt_key")
    @patch.object(KeyManager, 'get_keys')
    @raises(IncorrectPasswordException)
    def it_fails_authentication_if_a_key_can_not_be_validated(self, get_keys, decrypt_key):
        get_keys.return_value = [Mock()]
        decrypt_key.side_effect = IncorrectPasswordException

        data_source = DataSource('some_path')
        data_source.authenticate('password')

        assert data_source.is_authenticated() is False

    @patch("blimey.agile_keychain.data_source.gc")
    def it_unsets_keys_and_triggers_garbage_collection_on_deauthentication(self, gc):
        data_source = DataSource('some_path')
        data_source._keys = [1, 2, 3]
        data_source.deauthenticate()

        gc.collect.assert_called_with()

        assert data_source._keys == []
        assert data_source.is_authenticated() is False

    @patch("blimey.agile_keychain.data_source.crypto.generate_id")
    @patch("blimey.agile_keychain.data_source.time")
    def it_creates_items(self, time, generate_id):
        generate_id.return_value = 'random'
        time.return_value = 1400000000.00

        key3 = Mock()
        key3.identifier = 'abcd'
        key3.level = 'SL3'

        key5 = Mock()
        key5.identifier = 'efgh'
        key5.level = 'SL5'

        data_source = DataSource('some_path')
        data_source._keys = [key3, key5]

        item = data_source.create_item()

        assert type(item) is AgileKeychainItem
        assert item['uuid'] == 'random'
        assert item['createdAt'] == 1400000000
        assert item['location'] == ''
        assert item['locationKey'] == ''
        assert item['title'] == 'Untitled'
        assert item['typeName'] == 'passwords.Password'
        assert item['keyID'] == 'efgh'
        assert item['encrypted'] == {}

    @patch("blimey.agile_keychain.data_source.crypto.generate_id")
    def it_creates_items_item_initialised_with_data(self, generate_id):
        generate_id.return_value = 'random'

        key3 = Mock()
        key3.identifier = 'abcd'
        key3.level = 'SL3'

        key5 = Mock()
        key5.identifier = 'efgh'
        key5.level = 'SL5'

        data_source = DataSource('some_path')
        data_source._keys = [key3, key5]

        item = data_source.create_item({'title': 'Thing'})

        assert type(item) is AgileKeychainItem
        assert item['title'] == 'Thing'

    @patch.object(ItemManager, 'get_by_id')
    @patch("blimey.agile_keychain.data_source.crypto.generate_id")
    def it_guarantees_generated_item_id_is_unique(self, generate_id, get_item_by_id):
        get_item_by_id.side_effect = [Mock(), ItemNotFoundException]
        generate_id.side_effect = ['123', '567']

        key3 = Mock()
        key3.identifier = 'abcd'
        key3.level = 'SL3'

        key5 = Mock()
        key5.identifier = 'efgh'
        key5.level = 'SL5'

        data_source = DataSource('some_path')
        data_source._keys = [key3, key5]

        item = data_source.create_item()

        assert item['uuid'] == '567'

    @raises(UnauthenticatedDataSourceException)
    def it_throws_if_saving_an_item_with_deauthenticated_data_source(self):
        data_source = DataSource('some_path')
        data_source.save_item(Mock())

    @patch.object(KeyManager, 'get_keys')
    @patch.object(KeyManager, 'save_key')
    @patch("blimey.agile_keychain.data_source.crypto.encrypt_key")
    @patch("blimey.agile_keychain.data_source.crypto.decrypt_key")
    def it_re_encrypts_keys_when_password_is_changed(self, decrypt_key, encrypt_key, save_keys, get_keys):
        key3_encrypted = Mock()
        key3_decrypted = Mock()
        key3_reencrypted = Mock()
        key5_encrypted = Mock()
        key5_decrypted = Mock()
        key5_reencrypted = Mock()

        get_keys.return_value = [key3_encrypted, key5_encrypted]
        decrypt_key.side_effect = [key3_decrypted, key5_decrypted]
        encrypt_key.side_effect = [key3_reencrypted, key5_reencrypted]

        data_source = DataSource('some_path')
        data_source.authenticate('old_password')
        data_source.set_password('new_password')

        decrypt_key.assert_has_calls([call(key3_encrypted, 'old_password'), call(key5_encrypted, 'old_password')])
        encrypt_key.assert_has_calls([call(key3_decrypted, 'new_password'), call(key5_decrypted, 'new_password')])

        save_keys.assert_has_calls([call(key3_reencrypted), call(key5_reencrypted)])
