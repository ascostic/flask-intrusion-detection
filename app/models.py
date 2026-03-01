from datetime import datetime, timedelta
from app.extensions import mysql


# ==============================
# USER MANAGEMENT
# ==============================

def create_user(email, password_hash):
    cur = mysql.connection.cursor()
    cur.execute(
        "INSERT INTO users (email, password_hash) VALUES (%s, %s)",
        (email, password_hash)
    )
    mysql.connection.commit()
    cur.close()


def get_user_by_email(email):
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cur.fetchone()
    cur.close()
    return user


# ==============================
# LOGIN ATTEMPTS LOGGING
# ==============================

def log_login_attempt(user_id, ip_address, status):
    cur = mysql.connection.cursor()
    cur.execute(
        "INSERT INTO login_logs (user_id, ip_address, status) VALUES (%s, %s, %s)",
        (user_id, ip_address, status)
    )
    mysql.connection.commit()
    cur.close()


# ==============================
# IP BLOCKING
# ==============================

def is_ip_blocked(ip_address):
    cur = mysql.connection.cursor()
    cur.execute(
        "SELECT blocked_until FROM blocked_ips WHERE ip_address = %s",
        (ip_address,)
    )
    result = cur.fetchone()
    cur.close()

    if result and result['blocked_until'] > datetime.now():
        return True
    return False


def block_ip(ip_address):
    blocked_until = datetime.now() + timedelta(minutes=15)

    cur = mysql.connection.cursor()
    cur.execute(
        "INSERT INTO blocked_ips (ip_address, blocked_until) VALUES (%s, %s)",
        (ip_address, blocked_until)
    )
    mysql.connection.commit()
    cur.close()


def count_recent_failures(ip_address):
    cur = mysql.connection.cursor()
    cur.execute(
        """
        SELECT COUNT(*) as count FROM login_logs
        WHERE ip_address = %s AND status = 'FAILED'
        AND timestamp > NOW() - INTERVAL 5 MINUTE
        """,
        (ip_address,)
    )
    result = cur.fetchone()
    cur.close()
    return result['count']


# ==============================
# ACCOUNT LOCKING
# ==============================

def count_recent_user_failures(user_id):
    cur = mysql.connection.cursor()
    cur.execute(
        """
        SELECT COUNT(*) as count FROM login_logs
        WHERE user_id = %s AND status = 'FAILED'
        AND timestamp > NOW() - INTERVAL 5 MINUTE
        """,
        (user_id,)
    )
    result = cur.fetchone()
    cur.close()
    return result['count']


def lock_user_account(user_id):
    locked_until = datetime.now() + timedelta(minutes=15)

    cur = mysql.connection.cursor()
    cur.execute(
        "UPDATE users SET locked_until = %s WHERE id = %s",
        (locked_until, user_id)
    )
    mysql.connection.commit()
    cur.close()


def is_account_locked(user):
    if user.get("locked_until") and user["locked_until"] > datetime.now():
        return True
    return False


# ==============================
# SECURITY DASHBOARD
# ==============================

def get_security_stats():
    cur = mysql.connection.cursor()

    cur.execute("SELECT COUNT(*) as total FROM login_logs")
    total = cur.fetchone()["total"]

    cur.execute("SELECT COUNT(*) as failed FROM login_logs WHERE status='FAILED'")
    failed = cur.fetchone()["failed"]

    cur.execute("SELECT COUNT(*) as success FROM login_logs WHERE status='SUCCESS'")
    success = cur.fetchone()["success"]

    cur.execute(
        "SELECT COUNT(*) as blocked FROM blocked_ips WHERE blocked_until > NOW()"
    )
    blocked = cur.fetchone()["blocked"]

    cur.execute(
        "SELECT COUNT(*) as locked FROM users WHERE locked_until > NOW()"
    )
    locked = cur.fetchone()["locked"]

    cur.close()

    return {
        "total_attempts": total,
        "failed_attempts": failed,
        "successful_logins": success,
        "active_blocked_ips": blocked,
        "active_locked_accounts": locked
    }