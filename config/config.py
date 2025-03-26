import os
from pathlib import Path

BASE_DIR = Path(os.path.abspath(__file__)).parent.parent

DB = {
    "file_name": "a-crypt.db", # sqlite database name
    "dirname": "database" # sqlite database directory

}

LOG = {
    "app_log_file": "app.log",
    "db_log_file": "database.log",
    "users_log_file": "users.log",
    "dirname": "logs"
}

# Database path
DB_PATH = os.path.join(BASE_DIR, DB["dirname"], DB["file_name"])

# Log path
APP_LOG_PATH = os.path.join(BASE_DIR, LOG["dirname"], LOG["app_log_file"])
DB_LOG_PATH = os.path.join(BASE_DIR, LOG["dirname"], LOG["db_log_file"])
USERS_LOG_PATH = os.path.join(BASE_DIR, LOG["dirname"], LOG["users_log_file"])