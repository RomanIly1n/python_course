import base64
import hashlib
import hmac
import os

from cryptography.fernet import Fernet, InvalidToken

SALT_SIZE: int = 16


class DecryptionError(Exception):
    """Нужен, чтобы в cli отловить и указать свои имена ошибок
    (неверный ключ или сломанный токен)
    """


def new_salt() -> bytes:
    """Сгенерировать новую случайную соль"""
    return os.urandom(SALT_SIZE)


def hash_master(password: str, salt: bytes) -> bytes:
    """Получить хэш мастер-пароля"""
    return hashlib.sha256(salt + password.encode("utf-8")).digest()


def verify_master(password: str, salt: bytes, expected: bytes) -> bool:
    """Проверить мастер-пароль по хешу"""
    return hmac.compare_digest(hash_master(password, salt), expected)


def derive_key(password: str, salt: bytes) -> Fernet:
    """Создать ключ шифрования из мастер-пароля"""
    raw_key = hashlib.sha256(salt + password.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(raw_key))


def encrypt(fernet: Fernet, plaintext: str) -> str:
    """Зашифровываем"""
    return fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt(fernet: Fernet, token: str) -> str:
    """Расшифровываем"""
    try:
        return fernet.decrypt(token.encode("ascii")).decode("utf-8")
    except InvalidToken as exc:
        raise DecryptionError(
            "не удалось расшифровать запись: неверный ключ или данные повреждены"
        ) from exc


def b64e(data: bytes) -> str:
    """Перевод байты в base64-строку"""
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    """Обратный перевод base64-строки в байты"""
    return base64.b64decode(text.encode("ascii"))
