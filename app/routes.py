from flask import Blueprint, request, jsonify, render_template, current_app
from app.extensions import bcrypt, limiter
from app.models import (
    create_user,
    get_user_by_email,
    log_login_attempt,
    is_ip_blocked,
    count_recent_failures,
    block_ip,
    lock_user_account,
    count_recent_user_failures,
    is_account_locked,
    get_security_stats
)
from app.auth import generate_token, token_required


# =====================================================
# BLUEPRINT (THIS MUST EXIST AT TOP LEVEL)
# =====================================================
main = Blueprint("main", __name__)


# =====================================================
# BASIC ROUTES
# =====================================================

@main.route("/")
def home():
    return "Intrusion Detection System Running"


@main.route("/login-page")
def login_page():
    return render_template("login.html")


@main.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


# =====================================================
# REGISTER
# =====================================================

@main.route("/register", methods=["POST"])
def register():
    data = request.get_json()

    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    password_hash = bcrypt.generate_password_hash(password).decode("utf-8")

    try:
        create_user(email, password_hash)
        current_app.logger.info(f"User registered: {email}")
        return jsonify({"message": "User registered successfully"}), 201
    except Exception:
        current_app.logger.warning(f"Registration failed (duplicate): {email}")
        return jsonify({"error": "User already exists"}), 409


# =====================================================
# LOGIN (RATE LIMITED)
# =====================================================

@main.route("/login", methods=["POST"])
@limiter.limit("3 per minute")
def login():
    data = request.get_json()

    email = data.get("email")
    password = data.get("password")
    ip_address = request.remote_addr

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    # IP BLOCK CHECK
    if is_ip_blocked(ip_address):
        log_login_attempt(None, ip_address, "BLOCKED")
        current_app.logger.warning(f"Blocked IP attempt: {ip_address}")
        return jsonify({"error": "IP temporarily blocked"}), 403

    user = get_user_by_email(email)

    if not user:
        log_login_attempt(None, ip_address, "FAILED")
        current_app.logger.warning(
            f"Failed login (unknown user): {email} from {ip_address}"
        )
        return jsonify({"error": "Invalid credentials"}), 401

    # ACCOUNT LOCK CHECK
    if is_account_locked(user):
        current_app.logger.warning(
            f"Locked account login attempt: {email}"
        )
        return jsonify({"error": "Account temporarily locked"}), 403

    # PASSWORD CHECK
    if bcrypt.check_password_hash(user["password_hash"], password):
        log_login_attempt(user["id"], ip_address, "SUCCESS")

        current_app.logger.info(
            f"Successful login: {email} from {ip_address}"
        )

        if user.get("role") == "ADMIN":
            token = generate_token(user)
            return jsonify({"token": token}), 200

        return jsonify({"message": "Login successful"}), 200

    # FAILED PASSWORD
    log_login_attempt(user["id"], ip_address, "FAILED")

    current_app.logger.warning(
        f"Failed login (wrong password): {email} from {ip_address}"
    )

    # ACCOUNT FAILURE CHECK
    if count_recent_user_failures(user["id"]) >= 5:
        lock_user_account(user["id"])
        current_app.logger.critical(f"Account locked: {email}")
        return jsonify({"error": "Account temporarily locked"}), 403

    # IP FAILURE CHECK
    if count_recent_failures(ip_address) >= 5:
        block_ip(ip_address)
        current_app.logger.critical(f"IP blocked: {ip_address}")
        return jsonify({"error": "IP blocked"}), 403

    return jsonify({"error": "Invalid credentials"}), 401


# =====================================================
# PROTECTED SECURITY STATS
# =====================================================

@main.route("/security/stats", methods=["GET"])
@token_required(role="ADMIN")
def security_stats():
    stats = get_security_stats()
    return jsonify(stats), 200