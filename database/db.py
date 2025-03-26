from config import DB_PATH, DB_LOG_PATH
from logs import Logger
import sqlite3

# Logger instance for database operations
db_logger = Logger("db-logger", DB_LOG_PATH).get_logger()

class Database:
    """Database management class for handling user and file encryption records."""

    def __init__(self):
        """Initializes database connection and ensures required tables exist."""
        try:
            self.conn = sqlite3.connect(DB_PATH)
            self.cursor = self.conn.cursor()
            self.create_tables()
            db_logger.info("✅ Database connection established successfully.")
        
        except sqlite3.Error as e:
            db_logger.error(f"❌ Database connection error: {e}")

    def create_tables(self):
        """Creates necessary database tables if they do not exist."""
        try:
            # Users table
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE NOT NULL,
                    username TEXT UNIQUE NOT NULL,
                    full_name VARCHAR(125),
                    password TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Encrypted files table
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS encrypted_files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE NOT NULL,
                    user_id INTEGER,
                    file_name TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    encryption_key VARCHAR(255) NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            """)

            self.conn.commit()
            db_logger.info("✅ Database tables checked/created successfully.")
        except sqlite3.Error as e:
            db_logger.error(f"❌ Error creating tables: {e}")

    def add_user(self, username: str, full_name: str, password: str) -> bool:
        """Registers a new user in the database.

        Args:
            username (str): The username.
            full_name (str): Full name of the user.
            password (str): Hashed password of the user.

        Returns:
            bool: True if registration is successful, False if the username already exists.
        """
        try:
            self.cursor.execute(
                "INSERT INTO users (username, full_name, password) VALUES (?, ?, ?)", 
                (username, full_name, password)
            )
            self.conn.commit()
            db_logger.info(f"✅ New user registered: {username}/{full_name}")
            return True
        except sqlite3.IntegrityError:
            db_logger.warning(f"⚠️ User registration failed: Username {username} already exists.")
            return False

    def verify_user(self, username: str, password: str) -> int | None:
        """Verifies user credentials for login.

        Args:
            username (str): The username.
            password (str): The password.

        Returns:
            int | None: User ID if authentication is successful, None otherwise.
        """
        self.cursor.execute("SELECT id FROM users WHERE username = ? AND password = ?", (username, password))
        user = self.cursor.fetchone()
        if user:
            db_logger.info(f"🔓 User authenticated: {username}")
        else:
            db_logger.warning(f"⚠️ Failed login attempt for username: {username}")
        return user[0] if user else None

    def add_encrypted_file(self, user_id: int, file_name: str, file_path: str, encryption_key: str) -> None:
        """Stores information about an encrypted file in the database.

        Args:
            user_id (int): The ID of the user who encrypted the file.
            file_name (str): The name of the file.
            file_path (str): The path where the encrypted file is stored.
            encryption_key (str): The key used for encryption.
        """
        try:
            self.cursor.execute("""
                INSERT INTO encrypted_files (user_id, file_name, file_path, encryption_key)
                VALUES (?, ?, ?, ?)
            """, (user_id, file_name, file_path, encryption_key))
            self.conn.commit()
            db_logger.info(f"✅ Encrypted file added: {file_name} (User ID: {user_id})")
        except sqlite3.Error as e:
            db_logger.error(f"❌ Error adding encrypted file {file_name}: {e}")

    def delete_decrypted_file(self, file_path: str) -> bool:
        """Deletes a file record from the database after decryption.

        Args:
            file_path (str): The path of the decrypted file.

        Returns:
            bool: True if the file record was successfully deleted, False otherwise.
        """
        try:
            self.cursor.execute("SELECT file_path FROM encrypted_files WHERE file_path = ?", (file_path,))
            result = self.cursor.fetchone()
            
            if result:
                self.cursor.execute("DELETE FROM encrypted_files WHERE file_path = ?", (file_path,))
                self.conn.commit()
                db_logger.info(f"🗑️ File record deleted from database: {file_path}")
                return True
            else:
                db_logger.warning(f"⚠️ File not found in database: {file_path}")
                return False

        except Exception as e:
            db_logger.error(f"❌ Error deleting file record from database: {e}")
            return False

    def get_user_files(self, user_id: int):
        """Retrieves all encrypted files associated with a user.

        Args:
            user_id (int): The user's ID.

        Returns:
            list: A list of file paths associated with the user.
        """
        self.cursor.execute("SELECT file_path FROM encrypted_files WHERE user_id=?", (user_id,))
        files = [row[0] for row in self.cursor.fetchall()]
        db_logger.info(f"📂 Retrieved {len(files)} files for user ID {user_id}")
        return files

    def update_username(self, old_username: str, new_username: str) -> bool:
        """Updates a user's username.

        Args:
            old_username (str): The current username.
            new_username (str): The new username.

        Returns:
            bool: True if update was successful, False otherwise.
        """
        self.cursor.execute("UPDATE users SET username=? WHERE username=?", (new_username, old_username))
        self.conn.commit()
        success = self.cursor.rowcount > 0
        if success:
            db_logger.info(f"🆕 Username updated: {old_username} ➝ {new_username}")
        else:
            db_logger.warning(f"⚠️ Failed to update username: {old_username} not found.")
        return success

    def update_password(self, username: str, new_password: str) -> bool:
        """Updates a user's password.

        Args:
            username (str): The username.
            new_password (str): The new password (should be hashed).

        Returns:
            bool: True if update was successful, False otherwise.
        """
        self.cursor.execute("UPDATE users SET password=? WHERE username=?", (new_password, username))
        self.conn.commit()
        success = self.cursor.rowcount > 0
        if success:
            db_logger.info(f"🔑 Password updated for user: {username}")
        else:
            db_logger.warning(f"⚠️ Failed to update password for user: {username}")
        return success

    def close(self) -> None:
        """Closes the database connection."""
        self.conn.close()
        db_logger.info("🔌 Database connection closed.")
