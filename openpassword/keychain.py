from openpassword.exceptions import InvalidPasswordException
from openpassword.exceptions import KeychainLockedException


class Keychain:

    def __init__(self, repository):
        self._repository = repository
        self._locked = True

    def unlock(self, password, security_level="SL5"):
        master_key = self._repository.key_for_security_level(security_level)

        try:
            master_key.decrypt(password)
            self._locked = False
        except InvalidPasswordException as e:
            self._locked = True
            raise e

    def lock(self):
        self._locked = True

    def is_locked(self):
        return self._locked

    def get_item_by_unique_id(self, unique_id):
        self._check_is_locked()
        return self._repository.get_item_by_unique_id(unique_id)

    def _check_is_locked(self):
        if self.is_locked():
            raise KeychainLockedException
