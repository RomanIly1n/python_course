import json
import os
from pathlib import Path
from typing import TypedDict


class Entry(TypedDict):
    """Форма записи логина пароля"""

    login: str
    password: str


class VaultData(TypedDict):
    """Структура файла хранилища"""

    auth_salt: str
    verifier: str
    enc_salt: str
    entries: dict[str, Entry]


class StorageError(Exception):
    """Нужен, чтобы в cli отловить и указать свои имена ошибок
    Файл хранилища повреждён или не читается
    """


def exists(path: Path) -> bool:
    """Проверка: есть ли хранилище"""
    return path.is_file()


def load(path: Path) -> VaultData:
    """Прочитать хранилище из JSON"""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StorageError(f"не удалось прочитать хранилище {path}: {exc}") from exc

    required = {"auth_salt", "verifier", "enc_salt", "entries"}
    if not isinstance(raw, dict) or not required <= raw.keys():
        raise StorageError(f"файл {path} не похож на хранилище паролей")
    data: VaultData = raw  # type: ignore[assignment]
    return data


def save(path: Path, data: VaultData) -> None:
    """Сохранить хранилище в JSON"""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)
