import argparse
import sys
from core.user_manager import UserManager
from core.cipher import Cipher
from core.password_generator import PasswordGenerator
from config import APP_LOG_PATH
from logs import Logger

# Logger instance
app_logger = Logger("app-logger", APP_LOG_PATH).get_logger()
user_manager = UserManager()


def authenticate_user():
    """Prompt the user to enter username and password for authentication."""
    username = input("👤 Username: ").strip()
    password = input("🔑 Password: ").strip()

    user_id = user_manager.login_user(username, password)
    if user_id:
        app_logger.info(f"User authenticated: {username}")
        return user_id, username  # Return user_id and username if authenticated successfully
    else:
        app_logger.warning(f"Authentication failed for user: {username}")
        print("❌ Invalid username or password.")
        sys.exit(1)  # Exit the program on failed authentication


def register(args):
    """User registration function."""
    if user_manager.register_user(args.username, args.full_name, args.password):
        app_logger.info(f"User registered: {args.username}")
        print("✅ Registration successful!")
    else:
        app_logger.warning(f"Registration failed: Username {args.username} already exists.")
        print("❌ Username already exists.")


def get_user_files(args):
    """Retrieves and displays all files associated with the authenticated user."""
    user_id, username = authenticate_user()
    files = user_manager.get_user_files(user_id)

    if files:
        app_logger.info(f"📂 Retrieved {len(files)} files for user: {username}")
        print(f"📂 Files belonging to {username}:")
        for file in files:
            print(f"  - {file}")
    else:
        app_logger.info(f"📁 No files found for user: {username}")
        print("📁 No files found.")


def encrypt_text(args):
    """Encrypts a text message after authentication."""
    _, username = authenticate_user()
    cipher = Cipher(args.key, args.algorithm)
    encrypted_text = cipher.encrypt_text(args.text)
    app_logger.info(f"Text encrypted using {args.algorithm} by user {username}")
    print(f"🔒 Encrypted text: {encrypted_text}")


def decrypt_text(args):
    """Decrypts an encrypted message after authentication."""
    _, username = authenticate_user()
    cipher = Cipher(args.key, args.algorithm)
    decrypted_text = cipher.decrypt_text(args.encrypted_text)
    app_logger.info(f"Text decrypted using {args.algorithm} by user {username}")
    print(f"🔑 Decrypted text: {decrypted_text}")


def encrypt_file(args):
    """Encrypts a file after authentication."""
    _, username = authenticate_user()
    cipher = Cipher(args.key, args.algorithm)
    
    # 🔄 Agar output fayl berilmagan bo'lsa, avtomatik .acrypt qo'shamiz
    output_file = args.output_file if args.output_file else args.input_file + ".acrypt"
    
    cipher.encrypt_file(args.input_file, output_file)  # ✅ Agar yo‘q bo‘lsa, `.acrypt` kengaytmasi qo‘shiladi.
    app_logger.info(f"File {args.input_file} encrypted to {output_file} using {args.algorithm} by user {username}")
    print(f"🔒 File encrypted successfully: {output_file}")


def decrypt_file(args):
    """Decrypts a file after authentication."""
    _, username = authenticate_user()
    cipher = Cipher(args.key, args.algorithm)
    
    # 🔄 Agar output fayl berilmagan bo'lsa, asl nomini tiklaymiz
    output_file = args.output_file if args.output_file else args.input_file.replace(".acrypt", "")
    
    cipher.decrypt_file(args.input_file, output_file)  # ✅ Faqat `"A-Crypt"` headeri bor fayllarni qabul qiladi.
    app_logger.info(f"File {args.input_file} decrypted to {output_file} using {args.algorithm} by user {username}")
    print(f"🔑 File decrypted successfully: {output_file}")


def generate_password(args):
    """Generates a secure password."""
    password = PasswordGenerator.generate(length=args.length, use_digits=args.digits, use_special_chars=args.special)
    app_logger.info(f"Password generated with length {args.length} (digits: {args.digits}, special: {args.special})")
    print(f"🔑 Generated password: {password}")


def main():
    app_logger.info("Application started in CLI mode")
    parser = argparse.ArgumentParser(description="🔐 A-Crypt CLI - Encrypt & Decrypt files and messages securely")

    subparsers = parser.add_subparsers(title="Commands", description="Available commands")

    # Register
    register_parser = subparsers.add_parser("register", help="Register a new user")
    register_parser.add_argument("username", type=str, help="Username")
    register_parser.add_argument("full_name", type=str, help="Full name")
    register_parser.add_argument("password", type=str, help="Password")
    register_parser.set_defaults(func=register)

    # Get user files
    get_files_parser = subparsers.add_parser("get-user-files", help="Get all files belonging to the user")
    get_files_parser.set_defaults(func=get_user_files)

    # Encrypt text
    encrypt_text_parser = subparsers.add_parser("encrypt-text", help="Encrypt a text message")
    encrypt_text_parser.add_argument("text", type=str, help="Text to encrypt")
    encrypt_text_parser.add_argument("key", type=str, help="Encryption key")
    encrypt_text_parser.add_argument("--algorithm", type=str, choices=["AES", "CHACHA20"], default="AES", help="Encryption algorithm")
    encrypt_text_parser.set_defaults(func=encrypt_text)

    # Decrypt text
    decrypt_text_parser = subparsers.add_parser("decrypt-text", help="Decrypt an encrypted message")
    decrypt_text_parser.add_argument("encrypted_text", type=str, help="Text to decrypt")
    decrypt_text_parser.add_argument("key", type=str, help="Decryption key")
    decrypt_text_parser.add_argument("--algorithm", type=str, choices=["AES", "CHACHA20"], default="AES", help="Decryption algorithm")
    decrypt_text_parser.set_defaults(func=decrypt_text)

    # Encrypt file
    encrypt_file_parser = subparsers.add_parser("encrypt-file", help="Encrypt a file")
    encrypt_file_parser.add_argument("input_file", type=str, help="Input file path")
    encrypt_file_parser.add_argument("output_file", type=str, nargs="?", help="Output encrypted file path")
    encrypt_file_parser.add_argument("key", type=str, help="Encryption key")
    encrypt_file_parser.add_argument("--algorithm", type=str, choices=["AES", "CHACHA20"], default="AES", help="Encryption algorithm")
    encrypt_file_parser.set_defaults(func=encrypt_file)

    # Decrypt file
    decrypt_file_parser = subparsers.add_parser("decrypt-file", help="Decrypt a file")
    decrypt_file_parser.add_argument("input_file", type=str, help="Input encrypted file path")
    decrypt_file_parser.add_argument("output_file", type=str, nargs="?", help="Output decrypted file path")
    decrypt_file_parser.add_argument("key", type=str, help="Decryption key")
    decrypt_file_parser.add_argument("--algorithm", type=str, choices=["AES", "CHACHA20"], default="AES", help="Decryption algorithm")
    decrypt_file_parser.set_defaults(func=decrypt_file)

    # Generate password
    password_parser = subparsers.add_parser("generate-password", help="Generate a secure password")
    password_parser.add_argument("--length", type=int, default=16, help="Password length")
    password_parser.add_argument("--digits", action="store_true", help="Include digits in password")
    password_parser.add_argument("--special", action="store_true", help="Include special characters in password")
    password_parser.set_defaults(func=generate_password)

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()
    args.func(args)
