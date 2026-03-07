from app import mysql


def get_user_by_email(email):

    conn = mysql.connection
    cur = conn.cursor()

    cur.execute(
        """
        SELECT id, email, password_hash, role, locked_until
        FROM users
        WHERE email = %s
        """,
        (email,)
    )

    row = cur.fetchone()
    cur.close()

    if not row:
        return None

    return {
        "id": row["id"],
        "email": row["email"],
        "password_hash": row["password_hash"],
        "role": row["role"],
        "locked_until": row["locked_until"]
    }


def record_login_attempt(user_id, ip, success):

    conn = mysql.connection
    cur = conn.cursor()

    cur.execute(
        """
        INSERT INTO login_attempts (user_id, ip_address, success, timestamp)
        VALUES (%s, %s, %s, NOW())
        """,
        (user_id, ip, success)
    )

    conn.commit()
    cur.close()

def count_recent_failures(user_id):
    conn = mysql.connection
    cur = conn.cursor()

    cur.execute("""
        SELECT COUNT(*) AS failures
        FROM login_attempts
        WHERE user_id = %s
        AND success = 0
        AND timestamp > NOW() - INTERVAL 5 MINUTE
    """, (user_id,))

    result = cur.fetchone()
    cur.close()

    return result["failures"]

def lock_user_account(user_id):

    conn = mysql.connection
    cur = conn.cursor()

    cur.execute("""
        UPDATE users
        SET locked_until = NOW() + INTERVAL 15 MINUTE
        WHERE id = %s
    """, (user_id,))

    conn.commit()
    cur.close()

def get_security_stats():

    conn = mysql.connection
    cur = conn.cursor()

    # total attempts
    cur.execute("SELECT COUNT(*) AS total_attempts FROM login_attempts")
    total = cur.fetchone()["total_attempts"]

    # failed attempts
    cur.execute("SELECT COUNT(*) AS failed_attempts FROM login_attempts WHERE success = 0")
    failed = cur.fetchone()["failed_attempts"]

    # successful logins
    cur.execute("SELECT COUNT(*) AS successful_logins FROM login_attempts WHERE success = 1")
    success = cur.fetchone()["successful_logins"]

    # blocked IPs
    cur.execute("SELECT COUNT(*) AS blocked_ips FROM blocked_ips")
    blocked = cur.fetchone()["blocked_ips"]

    # locked accounts
    cur.execute("""
        SELECT COUNT(*) AS locked_accounts
        FROM users
        WHERE locked_until IS NOT NULL
        AND locked_until > NOW()
    """)
    locked = cur.fetchone()["locked_accounts"]

    cur.close()

    return {
        "total_attempts": total,
        "failed_attempts": failed,
        "successful_logins": success,
        "blocked_ips": blocked,
        "locked_accounts": locked
    }