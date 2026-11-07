import secrets
import string

LOWER = string.ascii_lowercase
UPPER = string.ascii_uppercase
DIGITS = string.digits
SPECIAL = "!@#$%^&*()-_=+[]{};:,.?"

MIN_LENGTH = 8


def generate_password(length: int = 12) -> str:
    if length < MIN_LENGTH:
        raise ValueError(f"длина пароля должна быть не меньше {MIN_LENGTH}")

    groups = [LOWER, UPPER, DIGITS, SPECIAL]
    alphabet = "".join(groups)

    chars = [secrets.choice(group) for group in groups]
    chars += [secrets.choice(alphabet) for _ in range(length - len(groups))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)
