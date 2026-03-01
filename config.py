import os


class BaseConfig:
    MYSQL_HOST = os.environ.get("MYSQL_HOST", "localhost")
    MYSQL_USER = os.environ.get("MYSQL_USER", "ids_user")
    MYSQL_PASSWORD = os.environ.get("MYSQL_PASSWORD", "StrongPassword123!")
    MYSQL_DB = os.environ.get("MYSQL_DB", "intrusion_detection")
    MYSQL_CURSORCLASS = "DictCursor"

    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key")

    JSONIFY_PRETTYPRINT_REGULAR = False


class DevelopmentConfig(BaseConfig):
    DEBUG = True


class ProductionConfig(BaseConfig):
    DEBUG = False
    TESTING = False