from flask import Blueprint, request, jsonify
from flask_bcrypt import Bcrypt
from app.models import (
    create_user,
    get_user_by_email,
    log_login_attempt,
    is_ip_blocked,
    count_recent_failures,
    block_ip
)

main = Blueprint('main', __name__)
bcrypt = Bcrypt()


# =============================
# HOME ROUTE
# =============================

@main.route('/')
def home():
    return "Intrusion Detection System Running"


# =============================
# REGISTER ROUTE
# =============================

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

    except Exception as e:
        if "Duplicate entry" in str(e):
            return jsonify({"error": "User already exists"}), 409
        return jsonify({"error": "Registration failed"}), 500


# =============================
# LOGIN WITH AUTOMATED BLOCKING
# =============================

@main.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    email = data.get('email')
    password = data.get('password')
    ip_address = request.remote_addr

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    # Step 1: Check if IP is already blocked
    if is_ip_blocked(ip_address):
        log_login_attempt(None, ip_address, "BLOCKED")
        return jsonify({"error": "IP temporarily blocked due to suspicious activity"}), 403

    user = get_user_by_email(email)

    # If user does not exist
    if not user:
        log_login_attempt(None, ip_address, "FAILED")

    else:
        # If password correct
        if bcrypt.check_password_hash(user['password_hash'], password):
            log_login_attempt(user['id'], ip_address, "SUCCESS")
            return jsonify({"message": "Login successful"}), 200

        else:
            log_login_attempt(user['id'], ip_address, "FAILED")

    # Step 2: Check failure count
    failures = count_recent_failures(ip_address)

    if failures >= 5:
        block_ip(ip_address)
        return jsonify({"error": "Too many failed attempts. IP blocked."}), 403

    return jsonify({"error": "Invalid credentials"}), 401
