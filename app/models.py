from app import mysql
from datetime import datetime, timedelta


# =============================
# USER MANAGEMENT
# =============================

def create_user(email, password_hash):
    cursor = mysql.connection.cursor()

    query = """
    INSERT INTO users (email, password_hash)
    VALUES (%s, %s)
    """

    cursor.execute(query, (email, password_hash))
    mysql.connection.commit()
    cursor.close()


def get_user_by_email(email):
    cursor = mysql.connection.cursor()

    query = "SELECT * FROM users WHERE email = %s"
    cursor.execute(query, (email,))
    user = cursor.fetchone()

    cursor.close()
    return user


def lock_user_account(user_id, minutes=15):
    cursor = mysql.connection.cursor()

    locked_until = datetime.now() + timedelta(minutes=minutes)

    query = """
    UPDATE users
    SET locked_until = %s
    WHERE id = %s
    """

    cursor.execute(query, (locked_until, user_id))
    mysql.connection.commit()

    cursor.close()


def is_account_locked(user):
    if user['locked_until'] is None:
        return False

    return user['locked_until'] > datetime.now()


def count_recent_user_failures(user_id, minutes=5):
    cursor = mysql.connection.cursor()

    query = """
    SELECT COUNT(*) AS fail_count
    FROM login_logs
    WHERE user_id = %s
    AND status = 'FAILED'
    AND timestamp > (NOW() - INTERVAL %s MINUTE)
    """

    cursor.execute(query, (user_id, minutes))
    result = cursor.fetchone()

    cursor.close()
    return result['fail_count']


# =============================
# LOGIN LOGGING
# =============================

def log_login_attempt(user_id, ip_address, status):
    cursor = mysql.connection.cursor()

    query = """
    INSERT INTO login_logs (user_id, ip_address, status)
    VALUES (%s, %s, %s)
    """

    cursor.execute(query, (user_id, ip_address, status))
    mysql.connection.commit()
    cursor.close()


# =============================
# IP-BASED INTRUSION DETECTION
# =============================

def is_ip_blocked(ip_address):
    cursor = mysql.connection.cursor()

    query = """
    SELECT * FROM blocked_ips
    WHERE ip_address = %s AND blocked_until > NOW()
    """

    cursor.execute(query, (ip_address,))
    result = cursor.fetchone()

    cursor.close()
    return result is not None


def block_ip(ip_address, minutes=15):
    cursor = mysql.connection.cursor()

    blocked_until = datetime.now() + timedelta(minutes=minutes)

    query = """
    INSERT INTO blocked_ips (ip_address, blocked_until)
    VALUES (%s, %s)
    ON DUPLICATE KEY UPDATE blocked_until = %s
    """

    cursor.execute(query, (ip_address, blocked_until, blocked_until))
    mysql.connection.commit()
    cursor.close()


def count_recent_failures(ip_address, minutes=2):
    cursor = mysql.connection.cursor()

    query = """
    SELECT COUNT(*) AS fail_count
    FROM login_logs
    WHERE ip_address = %s
    AND status = 'FAILED'
    AND timestamp > (NOW() - INTERVAL %s MINUTE)
    """

    cursor.execute(query, (ip_address, minutes))
    result = cursor.fetchone()

    cursor.close()
    return result['fail_count']

# =============================
# SECURITY ANALYTICS
# =============================

def get_security_stats():
    cursor = mysql.connection.cursor()

    # Total login attempts
    cursor.execute("SELECT COUNT(*) AS total FROM login_logs")
    total_attempts = cursor.fetchone()['total']

    # Failed attempts
    cursor.execute("SELECT COUNT(*) AS total FROM login_logs WHERE status = 'FAILED'")
    failed_attempts = cursor.fetchone()['total']

    # Successful logins
    cursor.execute("SELECT COUNT(*) AS total FROM login_logs WHERE status = 'SUCCESS'")
    successful_logins = cursor.fetchone()['total']

    # Active blocked IPs
    cursor.execute("SELECT COUNT(*) AS total FROM blocked_ips WHERE blocked_until > NOW()")
    active_blocked_ips = cursor.fetchone()['total']

    # Active locked accounts
    cursor.execute("SELECT COUNT(*) AS total FROM users WHERE locked_until IS NOT NULL AND locked_until > NOW()")
    active_locked_accounts = cursor.fetchone()['total']

    cursor.close()

    return {
        "total_attempts": total_attempts,
        "failed_attempts": failed_attempts,
        "successful_logins": successful_logins,
        "active_blocked_ips": active_blocked_ips,
        "active_locked_accounts": active_locked_accounts
    }