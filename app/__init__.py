import os
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask

from app.extensions import mysql, bcrypt, limiter


def create_app():
    app = Flask(
        __name__,
        template_folder="../templates",
        static_folder="../static"
    )

    # ==============================
    # Load Configuration
    # ==============================
    config_name = os.environ.get("FLASK_ENV", "development")

    if config_name == "production":
        from config import ProductionConfig
        app.config.from_object(ProductionConfig)
    else:
        from config import DevelopmentConfig
        app.config.from_object(DevelopmentConfig)

    # ==============================
    # Initialize Extensions
    # ==============================
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

    # ==============================
    # Production Logging
    # ==============================
    if not app.debug:
        if not os.path.exists("logs"):
            os.mkdir("logs")

        file_handler = RotatingFileHandler(
            "logs/security_app.log",
            maxBytes=10240,
            backupCount=5
        )

        file_handler.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s"
        ))

        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)

        app.logger.info("Security Application Startup")

    # ==============================
    # Register Blueprints
    # ==============================
    from app.routes import main
    app.register_blueprint(main)

    return app