from app import mysql


# Create new user
def create_user(email, password_hash):
    cursor = mysql.connection.cursor()

    query = """
    INSERT INTO users (email, password_hash)
    VALUES (%s, %s)
    """

    cursor.execute(query, (email, password_hash))
    mysql.connection.commit()

    cursor.close()


# Get user by email
def get_user_by_email(email):
    cursor = mysql.connection.cursor()

    query = "SELECT * FROM users WHERE email = %s"
    cursor.execute(query, (email,))

    user = cursor.fetchone()

    cursor.close()

    return user


# Log login attempts (intrusion detection logging)
def log_login_attempt(user_id, ip_address, status):
    cursor = mysql.connection.cursor()

    query = """
    INSERT INTO login_logs (user_id, ip_address, status)
    VALUES (%s, %s, %s)
    """

    cursor.execute(query, (user_id, ip_address, status))
    mysql.connection.commit()

    cursor.close()
