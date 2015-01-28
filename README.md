blimey
============

| [Stable](https://github.com/openpassword/blimey/tree/master) | [Unstable](https://github.com/openpassword/blimey/tree/develop) | [Scrutinizer](https://scrutinizer-ci.com/g/openpassword/blimey/) | [License](https://tldrlegal.com/license/mit-license) |
| --- | --- | --- | --- |
| ![Build Status](https://secure.travis-ci.org/openpassword/blimey.png?branch=master) |  ![!Status](https://secure.travis-ci.org/openpassword/blimey.png?branch=develop) | [![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/openpassword/blimey/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/openpassword/blimey/) | ![!License MIT](http://b.repl.ca/v1/License-MIT-blue.png) |

Usage
=====

```python
from blimey import AgileKeychain

# Construct a keychain with either a path to an existing keychain,
# or the path to where you want your keychain created
agilekeychain = AgileKeychain('path/to/keychain.agilekeychain')

# If the keychain doesn't exist, initialise it with a master password
agilekeychain.initialise('super-secret-password')

# Existing (and newly crated) keychains are unlocked by calling the unlock method
agilekeychain.unlock('super-secret-password')

# You can change the master password by calling set_password
agilekeychain.set_password('even-more-secret-password')

# Call create_item to initialise a new item
item = agilekeychain.create_item()

# Some boilerplate is put in place automatically
print(item)
# AgileKeychainItem({'encrypted': {}, 'title': 'Untitled', 'createdAt': 1422404797.4550807,
# 'typeName': 'passwords.Password', 'keyID': 'ED7D542C2EA24479407D3D5CB35637D2', 'location': '',
# 'uuid': 'CBA45A598A4A63D4DDD3C78E2CC11666', 'locationKey': ''})

# The item behaves like any dictionary
item['title'] = 'Usage Example'

# Anything stored under 'encrypted' key will be encrypted on save
item['encrypted'] = {
    'username': 'patrick',
    'password': 'correct horse battery staple'
}

# To save an item, pass it to the save_item method
agilekeychain.save_item(item)

# To access keychain items, you can iterate over the keychain, ...
for item in agilekeychain:
    print(item['title'])
# AgileKeychainItem({'encrypted': {}, 'title': 'Untitled', 'createdAt': 1422404797.4550807,
# 'typeName': 'passwords.Password', 'keyID': 'ED7D542C2EA24479407D3D5CB35637D2', 'updatedAt': 1422404900,
# 'location': '', 'uuid': 'CBA45A598A4A63D4DDD3C78E2CC11666', 'locationKey': ''})

# ... or access them directly by their UUID
print(agilekeychain['905B51856FD59A3C3AEF42A9FCE47E87'])

# When you are done you can lock the keychain by calling the lock method
agilekeychain.lock()
```
