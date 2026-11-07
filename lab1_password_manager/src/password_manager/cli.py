import argparse
import getpass
import sys
from pathlib import Path

from password_manager.crypto import DecryptionError
from password_manager.gen_pas import MIN_LENGTH, generate_password
from password_manager.manager import (
    NotInitializedError,
    PasswordManager,
    PasswordManagerError,
)
from password_manager.storage import StorageError

DEFAULT_VAULT = Path("vault.json")

MENU = """
1. Добавить запись
2. Список записей
3. Показать пароль
4. Удалить запись
5. Сгенерировать пароль
0. Выход"""


def build_parser() -> argparse.ArgumentParser:
    """Описать аргументы командной строки"""
    parser = argparse.ArgumentParser(
        prog="pm", description="Консольный менеджер паролей"
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--init", action="store_true", help="создать мастер-пароль")
    mode.add_argument("--unlock", action="store_true", help="войти и открыть меню")
    mode.add_argument("--generate", action="store_true", help="сгенерировать пароль")
    parser.add_argument(
        "--vault", type=Path, default=DEFAULT_VAULT, help="путь к файлу хранилища"
    )
    parser.add_argument(
        "--length", type=int, default=16, help=f"длина пароля (минимум {MIN_LENGTH})"
    )
    return parser


def cmd_init(pm: PasswordManager) -> int:
    """Создать хранилище: дважды спросить мастер-пароль и сравнить"""
    if pm.is_initialized():
        print(f"Ошибка: хранилище {pm.path} уже существует, перезаписать нельзя")
        return 1
    first = getpass.getpass("Новый мастер-пароль: ")
    second = getpass.getpass("Повторите мастер-пароль: ")
    if first != second:
        print("Ошибка: пароли не совпадают.")
        return 1
    pm.init_master(first)
    print(f"Хранилище создано: {pm.path}")
    return 0


def cmd_unlock(pm: PasswordManager) -> int:
    """Войти по мастер-паролю и запустить меню"""
    if not pm.is_initialized():
        raise NotInitializedError(
            f"хранилище {pm.path} не найдено, сначала выполните --init"
        )
    if not pm.unlock(getpass.getpass("Мастер-пароль: ")):
        print("Ошибка: неверный мастер-пароль")
        return 1
    print("Вход выполнен.")
    try:
        run_menu(pm)
    finally:
        pm.lock()
    return 0


def run_menu(pm: PasswordManager) -> None:
    """Цикл меню: читать номер пункта до выхода"""
    while True:
        print(MENU)
        try:
            choice = input("Выберите пункт: ").strip()
        except EOFError:
            print()
            return

        try:
            if choice == "0":
                return
            elif choice == "1":
                menu_add(pm)
            elif choice == "2":
                menu_list(pm)
            elif choice == "3":
                menu_get(pm)
            elif choice == "4":
                menu_delete(pm)
            elif choice == "5":
                print(generate_password())
            elif choice:
                print("Нет такого пункта")
        except (PasswordManagerError, ValueError, DecryptionError) as exc:
            print(f"Ошибка: {exc}")


def menu_add(pm: PasswordManager) -> None:
    """Добавить запись; пустой пароль — сгенерировать"""
    name = input("Сервис: ").strip()
    login = input("Логин: ").strip()
    pwd = getpass.getpass("Пароль (пусто —> сгенерировать): ")
    if not pwd:
        pwd = generate_password()
        print("Сгенерирован новый пароль")
    pm.add_entry(name, login, pwd)
    print(f"Запись '{name}' добавлена")


def menu_list(pm: PasswordManager) -> None:
    """Показать только названия записей"""
    names = pm.list_entries()
    if not names:
        print("Записей пока нет")
    for i, name in enumerate(names, start=1):
        print(f"{i}. {name}")


def menu_get(pm: PasswordManager) -> None:
    """Показать пароль после повторного ввода мастер-пароля"""
    name = input("Сервис: ").strip()
    if not pm.check_master(getpass.getpass("Подтвердите мастер-паролем: ")):
        print("Ошибка: неверный мастер-пароль")
        return
    login, pwd = pm.get_entry(name)
    print(f"Логин:  {login}\nПароль: {pwd}")


def menu_delete(pm: PasswordManager) -> None:
    """Удалить запись после подтверждения"""
    name = input("Сервис: ").strip()
    if input(f"Удалить '{name}'? [y/N]: ").strip().lower() != "y":
        print("Отменено")
        return
    pm.delete_entry(name)
    print(f"Запись '{name}' удалена")


def main() -> int:
    """Точка входа: разобрать аргументы и выполнить команду"""
    args = build_parser().parse_args()
    pm = PasswordManager(args.vault)
    try:
        if args.generate:
            print(generate_password(args.length))
            return 0
        if args.init:
            return cmd_init(pm)
        return cmd_unlock(pm)
    except (PasswordManagerError, StorageError, ValueError) as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nПрервано", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())