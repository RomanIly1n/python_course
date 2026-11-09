# Python course

Репозиторий с работами по курсу Python 2026.

## Содержание

| Папка | Что внутри |
|---|---|
| [`lab1_password_manager`](lab1_password_manager) | Лабораторная работа 1, тема Б1 — консольный менеджер паролей |
| [`leetcode`](leetcode) | Решения задач LeetCode |

## Лабораторная работа 1 — менеджер паролей

Консольное приложение: вход по мастер-паролю, записи (сервис, логин, пароль) хранятся в файле,
пароли в нём зашифрованы (Fernet), мастер-пароль хранится только как хэш SHA-256 с солью.

```bash
cd lab1_password_manager
uv sync
uv run pm --init      # создать хранилище
uv run pm --unlock    # войти и открыть меню
uv run pm --generate  # сгенерировать пароль
```

Подробности — в [README лабы](lab1_password_manager/README.md).

Проверки (ruff, mypy --strict, pytest) запускаются в GitHub Actions при каждом push.

## LeetCode

| № | Задача | Решение |
|---|---|---|
| 153 | Find Minimum in Rotated Sorted Array | [`leetcode/153`](leetcode/153) |
| 599 | Minimum Index Sum of Two Lists | [`leetcode/599`](leetcode/599) |
| 709 | To Lower Case | [`leetcode/709`](leetcode/709) |

В каждой папке есть решение и скриншот принятого решения.
