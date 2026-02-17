from flask import Blueprint, request, jsonify
from flask_bcrypt import Bcrypt
from app.models import create_user, get_user_by_email, log_login_attempt

main = Blueprint('main', __name__)
bcrypt = Bcrypt()

# Home route
@main.route('/')
def home():
    return "Intrusion Detection System Running"


# Register route
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


# Login route with intrusion logging
@main.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    email = data.get('email')
    password = data.get('password')

    ip_address = request.remote_addr

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    user = get_user_by_email(email)

    # User does not exist
    if not user:
        log_login_attempt(None, ip_address, "FAILED")
        return jsonify({"error": "Invalid credentials"}), 401

    # Correct password
    if bcrypt.check_password_hash(user['password_hash'], password):

        log_login_attempt(user['id'], ip_address, "SUCCESS")

        return jsonify({
            "message": "Login successful",
            "user": user['email']
        }), 200

    # Wrong password
    else:
        log_login_attempt(user['id'], ip_address, "FAILED")

        return jsonify({"error": "Invalid credentials"}), 401
