from nose.tools import raises

from blimey.agile_keychain import _crypto as crypto
from blimey.agile_keychain._key import EncryptedKey, DecryptedKey
from blimey.agile_keychain.agile_keychain_item import EncryptedAgileKeychainItem, AgileKeychainItem
from blimey.exceptions import IncorrectPasswordException


class CryptoSpec:
    @raises(IncorrectPasswordException)
    def it_throws_if_key_decryption_fails(self):
        key = self.get_key()
        crypto.decrypt_key(key, 'wrongpassword')

    def it_silently_decrypts_keys_with_correct_password(self):
        key = self.get_key()
        crypto.decrypt_key(key, 'masterpassword123')

    def it_reencrypts_keys_with_new_password(self):
        key = self.get_key()
        decrypted_key = crypto.decrypt_key(key, 'masterpassword123')
        encrypted_key = crypto.encrypt_key(decrypted_key, 'new_and_better_password')
        crypto.decrypt_key(encrypted_key, 'new_and_better_password')

    def it_creates_keys(self):
        encrypted_key = crypto.create_key('password', 'SL4', 10)
        crypto.decrypt_key(encrypted_key, 'password')

        assert encrypted_key.level == 'SL4'
        assert encrypted_key.iterations == 10

    def it_decrypts_items(self):
        encrypted_key = self.get_key()
        decrypted_key = crypto.decrypt_key(encrypted_key, 'masterpassword123')
        encrypted_item = self.get_item()
        decrypted_item = crypto.decrypt_item(encrypted_item, decrypted_key)

        assert decrypted_item['encrypted']['fields'][0]['value'] == 'someuser'
        assert decrypted_item['encrypted']['fields'][1]['value'] == 'password123'

    def it_encrypts_items(self):
        encrypted_key = self.get_key()
        decrypted_key = crypto.decrypt_key(encrypted_key, 'masterpassword123')
        decrypted_item = self.get_item()
        decrypted_item['encrypted'] = {'fields': [{'value': 'foo'}, {'value': 'bar'}, {'ball': '⚽'}]}

        encrypted_item = crypto.encrypt_item(decrypted_item, decrypted_key)
        redecrypted_item = crypto.decrypt_item(encrypted_item, decrypted_key)

        assert redecrypted_item['encrypted']['fields'][0]['value'] == 'foo'
        assert redecrypted_item['encrypted']['fields'][1]['value'] == 'bar'

    def it_byte_pads_to_specified_length(self):
        assert crypto.byte_pad(b'', 6) == b''
        assert crypto.byte_pad(b'abcd', 6) == b'abcd\x02\x02'
        assert crypto.byte_pad(b'abcdef', 6) == b'abcdef'

    def it_strips_byte_padding_at_specified_length(self):
        assert crypto.strip_byte_padding(b'', 6) == b''
        assert crypto.strip_byte_padding(b'abcd\x02\x02', 6) == b'abcd'
        assert crypto.strip_byte_padding(b'abcdef', 3) == b'abcdef'
        assert crypto.strip_byte_padding(b'abcdef', 6) == b'abcdef'

    @raises(ValueError)
    def it_throws_on_invalid_padding(self):
        crypto.strip_byte_padding(b'abc\x03\x03\x04', 6)

    def get_key(self):
        return EncryptedKey({
            'identifier': '98EB2E946008403280A3A8D9261018A4',
            'iterations': 25000,
            'level': 'SL5',
            'data':
                'U2FsdGVkX19CNF/5SazpsyC2/axBCsrpy1MBjTuulGu+hQgbMAT3COZgxGOfLUKG7VypKI/LpD3I5VxUP2NiIBqqLolwkTpQW79NJ'
                'OUYlqv+3argoTwz4JL9j4wyay4BJbclVkZMY8xn+UXf8TlSffLMj3aWbXqfv10stbPI8S9DzAQ/0rYFCHP83E82NueF6t7RXk9PZc'
                'sprqFcQpxdU0lxTWT5fJZscwdYy/M88bVgnTHfIwI1V9RxxAKj0lDkUBppCrkGhN7pWP4mvCR1+iI9xTAxASH5WQxNp7v+9T5btNK'
                '0hpe3532fuVbhEJ6XVVTbRMEJRYAGNXp4TOc0q8yaW//eSPCs/S/eYw6Dnai4MA0IZqpdydj7viaPrQR/z18Dv3jKq0K+E0fh8wn/'
                'EHrrIvhQofdyaX6slqIVx7jI9Mi7BGNz6qKeIZXdQekXiY9F1vxTsaMXtzRCO79id3rI/UmuBtTVmQ7kV/RVErWfxU98oDFTbMqqS'
                '4J59PMqfhamlBFlv5nfsC/oKPZrROdxG69RT7upWSLiN02PS3eIjgfEWfdDNInppwWv9ig/QZ3eeiVVSAcWqr6+zlXpXLTKV0T9pB'
                'We4Rq2cCTs32XQvz+3BphlKtSeUm50aL/ftiml1hv39Ks44JIwsZzFtXF3LhZVqwUFJsk+fdT3qDtxcEjuOuQ/TauPSUdD6duD0Yj'
                'MBKroRefGAxyrFCZ1gWHRLdLxRTu0JQUmhxN+T8AHoDJSY4KvNjaCFsxFLPbGLqT3zds7RjrAdchC/swhwG9iOsOU8qpaI7Ew1YVQ'
                '8d0Ms+SdSz/JCzuoIiaKigsIXvH6/BOwoTdM46qZIe+KgqbsOJc7YOMsuZosEacYwvD1LQ5waklXP8h/0LnbVnw0sCLc/h3JX78sW'
                'NWBJjnvT29oCDrALzlNbFrsjtubn27IZWhVeIqnN7cxLlbDgunK2FZsNJr1r5ACxwGMiC/klT3uZWQyyNkLCZkReQ8N9utskSFrhs'
                '9pv+lFDvWcfUbQfPt8GeP/C8fSdxHAA3DLtzlVcajaNHXF2zdofetZfSOS9y9pvbt6IuFrcNmMqlZQu3f7Tvvga3rSmqK8v08UiV8'
                '/KTxIqJ9oVS+/tFPe+aYGL9dJG9I2f7Yo9H8OvgNLDqK1tfULTppAdWpq863XxVz/MV6AP+bIRXuy9jviKjRrT2h2KVPM1fx3Fy0e'
                'fYro3FzLQlu86iVtQqn64zPGWP1Sfph2/IeRiCsFh+wKc6k/5X0TZEbsWpk0RRFN855SUYSUXgNwPqCHnS91zTm4f28CJ/mXqtdu9'
                'Y1wzwB/wTSilp4huyg5GkXyk+ZNuH7wqsOkdr8+Qg2Ckylh8hX18KVmP6DZ2EW+mykjzKkMXuLC6t4U89VtsUm4S8uX3rY5',
            'validation':
                'U2FsdGVkX19YMZ3cXoetbbnP+uMx6orlxhjYLIKtQxZnwqaN9A/NaF26+8gJPc/Ow7MubfnwX0ja0kgkRtrLVVonteZRYjoWhNi6k'
                'sg1YOWGUhO61PoUxHqJ7ZMPkn9XQw2dfNjfvi/CSVRcO4wUEBHzGGn+josnmknS2O8qQrUOysSYgsk3nSFByaFYEp4oKDTJePVeWU'
                'giy9ytGynWPzaeye8SxXymwo7le9ufNSFjGiUqwaKmLoyzCBRQXe5PPbSHl9wqZ7AePCMA5gt8DRKXcC8MKrWHQqGZPmwfJlkP/0P'
                'WPrpam90JnnKOH8pWwoIR+zeDZSZxpENhuaLgxLoq9MVBs5t/nO1kMZFepTMu2JBOo4nguFFEJ+Br/H5m0ith88q80/Xeq2c3tUIm'
                'KlE6GzFVCR2aFhiZnT/ZTbS8jt1ac/ygfXofuP1b2lNWK7WjwFz8GHtVMVT3NuSG6TN+LbpQwzVu9ofQ/ijXn9fe40OM4CDOm1fZr'
                'LK+NzdmmFKrD2wzcMultBp2bDJ0dL6xueNeVHDUjgLq1zjL1bHoi3aBqBrJuzyHBZ9VU4d5DT5ct78bT+df29kgbD3PA4wBsVEhCV'
                'bR+m/r21IVHv44BxCMV/eCIdLcsNSY4Nv7R/E9ppYlKx056hrfjOhkrlEIOOWqjzXFlJ1XVLjwv8JIb8QaovXNZ9B/6l1yCjtzeR5'
                'WXRtEG0d4aC61TKfHCGiasMZXbgzEg/UIk2cwecl8dhPqrPdysvlxLKKldX6kD7v8tISe/JwkfjiLZoiHUzN+P857KrNldWVBnL84'
                'cJAHQCs95fxK/d8G9VUr9SBcbuuz/qKdp9qM+ooi3yZZOrXSKxJIclXWGwwZmo9T9DDlRBi7D0kzjNvmxjoWk/8LD78tF6YcqSxuo'
                'gQut+JSGisXut460iX8GPzhjSKtsieA7fMynWlrFnUdEkPtgkSwJidxkWF7RjhP48iyLFDWET4aGtIJN0VbNf6c74i4EIvQIeOmVI'
                'uPaSUhmHePm4jZiC/j0zxQ/kP9Q20aM+VJV2x3D/ege3l+OrpeE/Tom0OLNzdVNtLALW9lHD3hqFbYl+hSwNT8/KbRherIYhJJo+5'
                'fK5A4EuHf6KCuKliePIAGVLbk/mCkKSnBuRh9O6zfmnnzOlsrtnuLoFXJQgp12gJFzIIOV0jNiwnQB4slxhbzySzv7kaZZWbzWqRV'
                'EbRxxZJsxhsTOpN3nOuhRCO2iE7hiRQwO5zw2MJ5uoA2PUtsLoo0R5C3kNEwTgL5IZnEa08ca7ogP9SSj58umqen3TLj48VcYJeXL'
                '7n6av2eDLDeQQLQkZoYN+D5U14IpYE2+mUKoaocQffAYeRx7eDgccPE8fVfpvfg98xD+9UXSS8OS7WZeeZHOxoIOQVj/3xb'
        })

    def get_item(self):
        return EncryptedAgileKeychainItem({
            'uuid': '9E7673CCBB5B4AC9A7A8838835CB7E83',
            'updatedAt': 1383517778,
            'locationKey': 'somewebsite.com',
            'folderUuid': '4A3D784D115F4279BDFCE46D0A162D57',
            'openContents': {
                'usernameHash': 'dde97596b7b3f628f89f1a95287f81eacece16b59c12684173f76ec45d6ab7b8',
                'tags': [
                    'tag1'
                ],
                'contentsHash': 'a15eef10'
            },
            'keyID': '98EB2E946008403280A3A8D9261018A4',
            'title': 'Some Website',
            'location': 'http://www.somewebsite.com',
            'encrypted':
                'U2FsdGVkX1/kMpBidzoNbFIdxvR/iS4Jk1YcYQL7F1ZXOEeslC7C4B6ZJkBNpBRF9J8b5a3WJBnAIpDOE8MYCeM4qUnZ1HOzzrEqc'
                'zPSWxESkHSqeuBHfu6Zv4gpsHqoim6hxCMp8AI6u7IrKWLS+g39Di3N73df/CG9U39YNwG6oVgf1bAESkrLyVTEz17/9o1J6EmGem'
                'IFWma6w3PkxTXl/YEcUYhOWJBUIZ0n6iYq+95IQBRjQ1QtObo3bdcURzdF5wg2HpCtF8FurqWSPYWzqH/TGxG4SKbIkiSPB40='
                '\u0000',
            'createdAt': 1383517434,
            'typeName': 'webforms.WebForm'
        })
