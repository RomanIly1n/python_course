from pathlib import Path

from cryptography.fernet import Fernet

from password_manager import crypto, storage
from password_manager.storage import Entry, VaultData


class PasswordManagerError(Exception):
    """Общая ошибка менеджера, cli.py ловит ее"""


class NotInitializedError(PasswordManagerError):
    """Хранилище ещё не создано"""


class AlreadyInitializedError(PasswordManagerError):
    """Хранилище уже есть, новое создать его нельзя."""


class LockedError(PasswordManagerError):
    """для выполнения надо  войти по мастер-паролю"""


class EntryNotFoundError(PasswordManagerError):
    """Записи с этим именем нет"""


class EntryExistsError(PasswordManagerError):
    """Запись с этим именем уже есть."""


class PasswordManager:
    """Менеджер паролей, работающий с одним файлом-хранилищем"""

    def __init__(self, path: Path) -> None:
        """Запомнить путь к хранилищу (файл пока не читается)"""
        self.path = path
        self._data: VaultData | None = None
        self._fernet: Fernet | None = None

    def is_initialized(self) -> bool:
        """Проверка: создано ли хранилище"""
        return storage.exists(self.path)

    def init_master(self, password: str) -> None:
        """Создать хранилище с новым мастер-паролем"""
        if self.is_initialized():
            raise AlreadyInitializedError(f"хранилище {self.path} уже существует")
        if not password:
            raise ValueError("мастер-пароль не может быть пустым")

        auth_salt = crypto.new_salt()
        enc_salt = crypto.new_salt()
        verifier = crypto.hash_master(password, auth_salt)

        data: VaultData = {
            "auth_salt": crypto.b64e(auth_salt),
            "verifier": crypto.b64e(verifier),
            "enc_salt": crypto.b64e(enc_salt),
            "entries": {},
        }
        storage.save(self.path, data)

    def check_master(self, password: str) -> bool:
        """Заранее проверяем мастер-пароль"""
        return self._verify(self._read(), password)

    def unlock(self, password: str) -> bool:
        """Войти по мастер-паролю"""
        self.lock()
        data = self._read()
        if not self._verify(data, password):
            return False
        self._data = data
        self._fernet = crypto.derive_key(password, crypto.b64d(data["enc_salt"]))
        return True

    def lock(self) -> None:
        """Выйти: забыть ключ и загруженные данные"""
        self._data = None
        self._fernet = None

    def is_unlocked(self) -> bool:
        """Выполнен ли вход"""
        return self._fernet is not None

    def add_entry(self, name: str, login: str, pwd: str) -> None:
        """Добавить запись и зашифровывание пароля"""
        data, fernet = self._require_unlocked()
        name = name.strip()
        if not name:
            raise ValueError("имя записи не может быть пустым")
        if name in data["entries"]:
            raise EntryExistsError(f"запись '{name}' уже существует")

        entry: Entry = {"login": login, "password": crypto.encrypt(fernet, pwd)}
        data["entries"][name] = entry
        self._persist()

    def list_entries(self) -> list[str]:
        """Вернуть отсортированные имена записей"""
        data, _ = self._require_unlocked()
        return sorted(data["entries"])

    def get_entry(self, name: str) -> tuple[str, str]:
        """Вернуть логин и расшифрованный пароль записи"""
        data, fernet = self._require_unlocked()
        entry = data["entries"].get(name)
        if entry is None:
            raise EntryNotFoundError(f"записи '{name}' нет")
        return entry["login"], crypto.decrypt(fernet, entry["password"])

    def delete_entry(self, name: str) -> None:
        """Удалить запись"""
        data, _ = self._require_unlocked()
        if name not in data["entries"]:
            raise EntryNotFoundError(f"записи '{name}' нет")
        del data["entries"][name]
        self._persist()

    def _read(self) -> VaultData:
        """Загрузить хранилище с диска"""
        if not self.is_initialized():
            raise NotInitializedError(
                f"хранилище {self.path} не найдено, сначала выполните --init"
            )
        return storage.load(self.path)

    def _persist(self) -> None:
        """Записать текущие данные на диск"""
        data, _ = self._require_unlocked()
        storage.save(self.path, data)

    def _require_unlocked(self) -> tuple[VaultData, Fernet]:
        """Вернуть данные и ключ или выбросить LockedError"""
        if self._data is None or self._fernet is None:
            raise LockedError("сначала войдите по мастер-паролю")
        return self._data, self._fernet

    @staticmethod
    def _verify(data: VaultData, password: str) -> bool:
        """Сравнить пароль с verifier из данных хранилища"""
        return crypto.verify_master(
            password,
            crypto.b64d(data["auth_salt"]),
            crypto.b64d(data["verifier"]),
        )
