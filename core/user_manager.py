from database.db import Database
from core.password_generator import hash_password
from logs import Logger
from config import USERS_LOG_PATH

# Logger instance for user management operations
user_logger = Logger("user-manager", USERS_LOG_PATH).get_logger()

class UserManager:
    """Handles user-related operations such as registration, authentication, and file management."""

    def __init__(self):
        """Initializes the UserManager with a database connection."""
        self.db = Database()
        user_logger.info("✅ UserManager initialized successfully.")

    def register_user(self, username: str, full_name: str, password: str) -> bool:
        """Registers a new user after hashing their password.

        Args:
            username (str): The chosen username.
            full_name (str): The full name of the user.
            password (str): The raw password (will be hashed before storing).

        Returns:
            bool: True if registration is successful, False if the username already exists.
        """
        hashed_password = hash_password(password)
        success = self.db.add_user(username, full_name, hashed_password)

        if success:
            user_logger.info(f"✅ User registered successfully: {username}")
        else:
            user_logger.warning(f"⚠️ Registration failed: Username {username} already exists.")

        return success

    def login_user(self, username: str, password: str) -> int | None:
        """Authenticates a user by verifying their hashed password.

        Args:
            username (str): The username.
            password (str): The raw password (will be hashed before verification).

        Returns:
            int | None: User ID if authentication is successful, None otherwise.
        """
        hashed_password = hash_password(password)
        user_id = self.db.verify_user(username, hashed_password)

        if user_id:
            user_logger.info(f"🔓 User logged in successfully: {username} (User ID: {user_id})")
        else:
            user_logger.warning(f"⚠️ Failed login attempt: {username}")

        return user_id

    def get_user_files(self, user_id: int) -> list[str]:
        """Retrieves all encrypted files associated with a given user.

        Args:
            user_id (int): The ID of the user whose files are to be retrieved.

        Returns:
            list[str]: A list of file paths associated with the user.
        """
        files = self.db.get_user_files(user_id)

        if files:
            user_logger.info(f"📂 Retrieved {len(files)} files for User ID: {user_id}")
        else:
            user_logger.info(f"📁 No files found for User ID: {user_id}")

        return files
