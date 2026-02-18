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
# INTRUSION DETECTION LOGIC
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
