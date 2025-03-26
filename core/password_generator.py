import string
import secrets
import hashlib


def hash_password(password: str, algorithm: str = "sha256") -> str:
    """
    Hashes a password securely using the specified algorithm.

    Args:
        password (str): The password to be hashed.
        algorithm (str): The hashing algorithm to use ('sha256', 'sha512', 'md5').

    Returns:
        str: The hashed password in hexadecimal format.

    Raises:
        ValueError: If an unsupported algorithm is specified.
    """
    supported_algorithms = {
        "sha256": hashlib.sha256,
        "sha512": hashlib.sha512,
        "md5": hashlib.md5  # Not recommended for security
    }

    hash_func = supported_algorithms.get(algorithm.lower(), hashlib.sha256)  # Default to sha256
    return hash_func(password.encode()).hexdigest()


class PasswordGenerator:
    @staticmethod
    def generate(length: int = 16, use_digits: bool = True, use_special_chars: bool = True) -> str:
        if length < 4:
            raise ValueError("Password length must be at least 4 characters.")

        alphabet = string.ascii_letters  # Uppercase & lowercase letters
        if use_digits:
            alphabet += string.digits  # Adds digits (0-9)
        if use_special_chars:
            alphabet += string.punctuation  # Adds special characters

        return ''.join(secrets.choice(alphabet) for _ in range(length))
