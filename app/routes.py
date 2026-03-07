from flask import Blueprint, request, jsonify
import bcrypt
import jwt
from datetime import datetime, timedelta

from app.models import (
    get_user_by_email,
    record_login_attempt,
    get_security_stats,
    count_recent_failures,
    lock_user_account
)

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

    # user must exist first
    if not user:
        return jsonify({"error": "invalid credentials"}), 401

    # brute force detection
    failures = count_recent_failures(user["id"])

    if failures >= 5:
        lock_user_account(user["id"])
        return jsonify({"error": "account temporarily locked"}), 403

    # password verification
    if not bcrypt.checkpw(
        password.encode("utf-8"),
        user["password_hash"].encode("utf-8")
    ):
        record_login_attempt(user["id"], ip, False)
        return jsonify({"error": "invalid credentials"}), 401

    # successful login
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