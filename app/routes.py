from flask import Blueprint, request, jsonify
from app.extensions import bcrypt, limiter
from app.models import (
    create_user,
    get_user_by_email,
    log_login_attempt,
    is_ip_blocked,
    block_ip,
    add_risk,
    get_risk,
    reset_risk,
    get_security_stats
)
from app.auth import generate_token, token_required

main = Blueprint("main", __name__)

RISK_THRESHOLD = 70


# ======================================
# HOME
# ======================================

@main.route("/")
def home():
    return "Intrusion Detection System Running"


# ======================================
# REGISTER
# ======================================

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
        return jsonify({"message": "User registered successfully"}), 201
    except Exception:
        return jsonify({"error": "User already exists"}), 409


# ======================================
# LOGIN WITH RISK ENGINE
# ======================================

@main.route("/login", methods=["POST"])
@limiter.limit("3 per minute")
def login():
    data = request.get_json()

    email = data.get("email")
    password = data.get("password")
    ip_address = request.remote_addr

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    # 🔴 STEP 1 — Check if already blocked
    if is_ip_blocked(ip_address):
        log_login_attempt(None, ip_address, "BLOCKED")
        return jsonify({"error": "IP temporarily blocked"}), 403

    # 🔴 STEP 2 — Check current risk BEFORE processing
    current_risk = get_risk("IP", ip_address)
    if current_risk >= RISK_THRESHOLD:
        block_ip(ip_address)
        return jsonify({"error": "IP blocked due to high risk score"}), 403

    user = get_user_by_email(email)

    # ======================================
    # USER NOT FOUND
    # ======================================
    if not user:
        log_login_attempt(None, ip_address, "FAILED")

        new_risk = add_risk("IP", ip_address, 10)

        if new_risk >= RISK_THRESHOLD:
            block_ip(ip_address)
            return jsonify({"error": "IP blocked due to high risk score"}), 403

        return jsonify({"error": "Invalid credentials"}), 401

    # ======================================
    # PASSWORD CORRECT
    # ======================================
    if bcrypt.check_password_hash(user["password_hash"], password):
        log_login_attempt(user["id"], ip_address, "SUCCESS")

        reset_risk("IP", ip_address)
        reset_risk("USER", user["id"])

        token = generate_token(user["id"], user["email"], user["role"])

        return jsonify({
            "message": "Login successful",
            "token": token
        }), 200

    # ======================================
    # PASSWORD WRONG
    # ======================================
    log_login_attempt(user["id"], ip_address, "FAILED")

    ip_risk = add_risk("IP", ip_address, 10)
    user_risk = add_risk("USER", user["id"], 10)

    if ip_risk >= RISK_THRESHOLD:
        block_ip(ip_address)
        return jsonify({"error": "IP blocked due to high risk score"}), 403

    if user_risk >= RISK_THRESHOLD:
        return jsonify({"error": "Account flagged due to suspicious activity"}), 403

    return jsonify({"error": "Invalid credentials"}), 401


# ======================================
# SECURITY DASHBOARD (Protected)
# ======================================

@main.route("/security/stats", methods=["GET"])
@token_required
def security_stats(current_user):
    stats = get_security_stats()
    return jsonify(stats), 200