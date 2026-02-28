import os

class Config:
    MYSQL_HOST = 'localhost'
    MYSQL_USER = 'ids_user'
    MYSQL_PASSWORD = 'StrongPassword123!'
    MYSQL_DB = 'intrusion_detection'
    MYSQL_CURSORCLASS = 'DictCursor'

    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key")