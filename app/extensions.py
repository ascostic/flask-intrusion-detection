from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import MySQLdb.cursors

mysql = MySQL()
bcrypt = Bcrypt()

limiter = Limiter(
    key_func=get_remote_address,
    storage_uri="redis://127.0.0.1:6379"
)


def configure_mysql(app):
    app.config["MYSQL_CURSORCLASS"] = "DictCursor"