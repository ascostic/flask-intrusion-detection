from flask import Flask
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from config import Config


# Extensions
mysql = MySQL()
bcrypt = Bcrypt()
limiter = Limiter(key_func=get_remote_address)


def create_app():
    app = Flask(
        __name__,
        template_folder="../templates",
        static_folder="../static"
    )

    # Load configuration
    app.config.from_object(Config)

    # Initialize extensions
    mysql.init_app(app)
    bcrypt.init_app(app)
    limiter.init_app(app)

    # ==============================
    # Security Headers
    # ==============================
    @app.after_request
    def apply_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    # Register Blueprints
    from app.routes import main
    app.register_blueprint(main)

    return app