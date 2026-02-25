from flask import Blueprint, request, jsonify, render_template
from flask_bcrypt import Bcrypt

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


main = Blueprint('main', __name__)
bcrypt = Bcrypt()


# ==============================
# HOME ROUTE
# ==============================

@main.route('/')
def home():
    return "Intrusion Detection System Running"


# ==============================
# FRONTEND ROUTES
# ==============================

@main.route('/login-page')
def login_page():
    return render_template("login.html")


@main.route('/dashboard')
def dashboard():
    return render_template("dashboard.html")


# ==============================
# REGISTER ROUTE
# ==============================

@main.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    try:
        create_user(email, password_hash)
        return jsonify({"message": "User registered successfully"}), 201
    except Exception:
        return jsonify({"error": "User already exists"}), 409


# ==============================
# LOGIN ROUTE (JWT for ADMIN)
# ==============================

@main.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    email = data.get('email')
    password = data.get('password')
    ip_address = request.remote_addr

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    # Check IP block
    if is_ip_blocked(ip_address):
        log_login_attempt(None, ip_address, "BLOCKED")
        return jsonify({"error": "IP temporarily blocked due to suspicious activity"}), 403

    user = get_user_by_email(email)

    if not user:
        log_login_attempt(None, ip_address, "FAILED")
    else:
        # Check account lock
        if is_account_locked(user):
            return jsonify({"error": "Account temporarily locked"}), 403

        # Verify password
        if bcrypt.check_password_hash(user['password_hash'], password):
            log_login_attempt(user['id'], ip_address, "SUCCESS")

            # If admin → generate JWT
            if user['role'] == 'ADMIN':
                token = generate_token(user)
                return jsonify({
                    "message": "Admin login successful",
                    "token": token
                }), 200

            return jsonify({"message": "Login successful"}), 200

        else:
            log_login_attempt(user['id'], ip_address, "FAILED")

            failures = count_recent_user_failures(user['id'])

            if failures >= 5:
                lock_user_account(user['id'])
                return jsonify({
                    "error": "Account temporarily locked due to repeated failed attempts"
                }), 403

    # IP failure tracking
    failures_ip = count_recent_failures(ip_address)

    if failures_ip >= 5:
        block_ip(ip_address)
        return jsonify({"error": "Too many failed attempts. IP blocked."}), 403

    return jsonify({"error": "Invalid credentials"}), 401


# ==============================
# PROTECTED SECURITY STATS
# ==============================

@main.route('/security/stats', methods=['GET'])
@token_required(role='ADMIN')
def security_stats():
    stats = get_security_stats()
    return jsonify(stats), 200