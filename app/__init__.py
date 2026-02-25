from flask import Flask
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
from config import Config

mysql = MySQL()
bcrypt = Bcrypt()


def create_app():
    app = Flask(
        __name__,
        template_folder="../templates",
        static_folder="../static"
    )

    app.config.from_object(Config)

    mysql.init_app(app)
    bcrypt.init_app(app)

    from app.routes import main
    app.register_blueprint(main)

    return app