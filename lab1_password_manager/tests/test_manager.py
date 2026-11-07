import json
from pathlib import Path

import pytest

from password_manager import crypto
from password_manager.gen_pas import generate_password
from password_manager.manager import (
    AlreadyInitializedError,
    EntryNotFoundError,
    LockedError,
    PasswordManager,
)

MASTER = "Master-tesrik"


@pytest.fixture
def pm(tmp_path: Path) -> PasswordManager:
    """Созданный и открытый менеджер во временной папке."""
    manager = PasswordManager(tmp_path / "vault.json")
    manager.init_master(MASTER)
    manager.unlock(MASTER)
    return manager


def test_unlock_correct_and_wrong(tmp_path: Path) -> None:
    manager = PasswordManager(tmp_path / "vault.json")
    manager.init_master(MASTER)
    assert manager.unlock("wrong") is False
    assert manager.unlock(MASTER) is True
    assert manager.is_unlocked()


def test_init_twice_forbidden(pm: PasswordManager) -> None:
    with pytest.raises(AlreadyInitializedError):
        pm.init_master("other")


def test_add_list_get(pm: PasswordManager) -> None:
    pm.add_entry("github", "romanily", "gh-secret")
    assert pm.list_entries() == ["github"]
    assert pm.get_entry("github") == ("romanily", "gh-secret")


def test_delete(pm: PasswordManager) -> None:
    pm.add_entry("github", "romanily", "gh-secret")
    pm.delete_entry("github")
    assert pm.list_entries() == []
    with pytest.raises(EntryNotFoundError):
        pm.get_entry("github")


def test_no_plain_text_in_file(pm: PasswordManager) -> None:
    pm.add_entry("github", "romanily", "gh-secret")
    text = pm.path.read_text(encoding="utf-8")
    assert MASTER not in text
    assert "gh-secret" not in text
    assert json.loads(text)["entries"]["github"]["password"].startswith("gAAAA")


def test_locked_after_lock(pm: PasswordManager) -> None:
    pm.lock()
    with pytest.raises(LockedError):
        pm.list_entries()


def test_salt_makes_hashes_different() -> None:
    salt1, salt2 = crypto.new_salt(), crypto.new_salt()
    assert crypto.hash_master(MASTER, salt1) != crypto.hash_master(MASTER, salt2)


def test_generate_password() -> None:
    pwd = generate_password(20)
    assert len(pwd) == 20
    assert any(c.islower() for c in pwd)
    assert any(c.isupper() for c in pwd)
    assert any(c.isdigit() for c in pwd)
    assert any(not c.isalnum() for c in pwd)


def test_generate_too_short() -> None:
    with pytest.raises(ValueError):
        generate_password(3)