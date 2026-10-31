"""Password verification and atomic credential updates for the single admin account."""
import hashlib
import hmac
import json
import os
import secrets
import tempfile
import threading
from pathlib import Path

LOCK = threading.RLock()
ITERATIONS = 310000


def digest(password, salt, iterations=ITERATIONS):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), iterations).hex()


def save_record(path, password):
    salt = secrets.token_hex(24)
    record = {'username': 'admin', 'salt': salt, 'iterations': ITERATIONS, 'hash': digest(password, salt)}
    path = Path(path)
    with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, prefix='.auth-', delete=False) as file:
        temporary = Path(file.name)
        json.dump(record, file)
    try:
        os.chmod(temporary, 0o600)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def record(path, initial_password_file):
    with LOCK:
        path = Path(path)
        if not path.exists():
            save_record(path, Path(initial_password_file).read_text().strip())
        return json.loads(path.read_text())


def verify(path, initial_password_file, username, password):
    if not isinstance(password, str) or len(password) > 256 or username != 'admin':
        return False
    value = record(path, initial_password_file)
    return hmac.compare_digest(digest(password, value['salt'], value['iterations']), value['hash'])


def change_password(path, initial_password_file, current, replacement):
    if not isinstance(replacement, str) or not 12 <= len(replacement) <= 128:
        raise ValueError('Use a new password between 12 and 128 characters')
    with LOCK:
        if not verify(path, initial_password_file, 'admin', current):
            raise ValueError('The current password is incorrect')
        if hmac.compare_digest(current.encode(), replacement.encode()):
            raise ValueError('Choose a password different from the current password')
        save_record(path, replacement)
