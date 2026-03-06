from flask import Blueprint, request, jsonify
import bcrypt
import jwt
from datetime import datetime, timedelta

from app.models import get_user_by_email, record_login_attempt, get_security_stats

main = Blueprint("main", __name__)


@main.route("/")
def home():
    return "Intrusion Detection System Running"


@main.route("/login", methods=["POST"])
def login():

    data = request.get_json()

    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "missing credentials"}), 400

    ip = request.remote_addr

    user = get_user_by_email(email)

    if not user:
        record_login_attempt(user["id"], ip, False)
        return jsonify({"error": "invalid credentials"}), 401

    if not bcrypt.checkpw(
    password.encode("utf-8"),
    user["password_hash"].encode("utf-8") ):
        record_login_attempt(user["id"], ip, False)
        return jsonify({"error": "invalid credentials"}), 401

    record_login_attempt(user["id"], ip, True)

    token = jwt.encode(
        {
            "user_id": user["id"],
            "exp": datetime.utcnow() + timedelta(hours=1)
        },
        "supersecretkey",
        algorithm="HS256"
    )

    return jsonify({"token": token})


@main.route("/security/stats")
def stats():

    stats = get_security_stats()

    return jsonify(stats)