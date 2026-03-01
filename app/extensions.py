from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

mysql = MySQL()
bcrypt = Bcrypt()
limiter = Limiter(key_func=get_remote_address)