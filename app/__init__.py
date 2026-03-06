import os
import logging
import traceback
from logging.handlers import RotatingFileHandler

from flask import Flask, jsonify
from app.extensions import mysql, bcrypt, limiter


def create_app():
    app = Flask(
        __name__,
        template_folder="../templates",
        static_folder="../static"
    )

    # ==========================================
    # Load Configuration
    # ==========================================
    env = os.environ.get("FLASK_ENV", "development")

    if env == "production":
        from config import ProductionConfig
        app.config.from_object(ProductionConfig)
    else:
        from config import DevelopmentConfig
        app.config.from_object(DevelopmentConfig)

    # 🔥 IMPORTANT FIX — Use DictCursor
    app.config["MYSQL_CURSORCLASS"] = "DictCursor"

    # ==========================================
    # Initialize Extensions
    # ==========================================
    mysql.init_app(app)
    bcrypt.init_app(app)
    limiter.init_app(app)

    # ==========================================
    # Security Headers
    # ==========================================
    @app.after_request
    def apply_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    # ==========================================
    # Production Logging
    # ==========================================
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

    # ==========================================
    # Centralized Error Handling
    # ==========================================

    @app.errorhandler(400)
    def handle_bad_request(e):
        return jsonify({
            "status": "error",
            "code": 400,
            "message": "Bad request"
        }), 400

    @app.errorhandler(401)
    def handle_unauthorized(e):
        return jsonify({
            "status": "error",
            "code": 401,
            "message": "Unauthorized"
        }), 401

    @app.errorhandler(403)
    def handle_forbidden(e):
        return jsonify({
            "status": "error",
            "code": 403,
            "message": "Forbidden"
        }), 403

    @app.errorhandler(404)
    def handle_not_found(e):
        return jsonify({
            "status": "error",
            "code": 404,
            "message": "Resource not found"
        }), 404

    @app.errorhandler(429)
    def handle_rate_limit(e):
        return jsonify({
            "status": "error",
            "code": 429,
            "message": "Too many requests"
        }), 429

    @app.errorhandler(500)
    def handle_internal_error(e):
        app.logger.error("Internal Server Error")
        app.logger.error(traceback.format_exc())

        return jsonify({
            "status": "error",
            "code": 500,
            "message": "Internal server error"
        }), 500

    #@app.errorhandler(Exception)
    #def handle_exception(e):
     #   return {
     #   "error": str(e),
      #  "type": type(e).__name__
    #}, 500

    # ==========================================
    # Register Blueprints
    # ==========================================
    from app.routes import main
    app.register_blueprint(main)

    return app