"""
Encrypts/decrypts users' stored email app-passwords at rest.

Uses Fernet (symmetric, authenticated encryption) from the `cryptography`
package. The key comes from config.ENCRYPTION_KEY (put it in your .env).

Generate a key with:
    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
"""

from cryptography.fernet import Fernet

from config import ENCRYPTION_KEY

_fernet = Fernet(ENCRYPTION_KEY.encode())


def encrypt(plain_text):
    if plain_text is None:
        return None
    return _fernet.encrypt(plain_text.encode()).decode()


def decrypt(token):
    if token is None:
        return None
    return _fernet.decrypt(token.encode()).decode()
