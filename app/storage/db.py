"""MySQL users table + salted hashing (no chat storage)."""

import argparse
import os
import secrets
import hashlib
import pymysql
from typing import Tuple
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Database connection configuration
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", "3307"))
DB_USER = os.getenv("DB_USER", "scuser")
DB_PASSWORD = os.getenv("DB_PASSWORD", "scpass")
DB_NAME = os.getenv("DB_NAME", "securechat")


def get_connection():
    """Get a connection to the MySQL database."""
    return pymysql.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor
    )


def init_db():
    """Initialize the database by creating the users table."""
    connection = get_connection()
    try:
        with connection.cursor() as cursor:
            # Create users table if it doesn't exist
            create_table_sql = """
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(64) NOT NULL,
                salt VARCHAR(32) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_username (username)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """
            cursor.execute(create_table_sql)
        connection.commit()
        print(f"Database '{DB_NAME}' initialized successfully. Users table created.")
    except Exception as e:
        print(f"Error initializing database: {e}")
        raise
    finally:
        connection.close()


def hash_password(password: str, salt: bytes = None) -> Tuple[str, str]:
    """
    Hash a password with a salt using SHA-256.
    
    Args:
        password: Plain text password
        salt: Optional salt bytes. If None, a random salt is generated.
    
    Returns:
        Tuple of (hex hash, hex salt)
    """
    if salt is None:
        salt = secrets.token_bytes(16)
    
    # Combine salt and password, then hash
    salted_password = salt + password.encode("utf-8")
    password_hash = hashlib.sha256(salted_password).hexdigest()
    
    return password_hash, salt.hex()


def verify_password(password: str, stored_hash: str, stored_salt: str) -> bool:
    """
    Verify a password against a stored hash and salt.
    
    Args:
        password: Plain text password to verify
        stored_hash: Stored password hash (hex)
        stored_salt: Stored salt (hex)
    
    Returns:
        True if password matches, False otherwise
    """
    salt_bytes = bytes.fromhex(stored_salt)
    computed_hash, _ = hash_password(password, salt_bytes)
    return computed_hash == stored_hash


def register_user(username: str, password: str) -> bool:
    """
    Register a new user in the database.
    
    Args:
        username: Username
        password: Plain text password
    
    Returns:
        True if user was registered successfully, False if user already exists
    """
    connection = get_connection()
    try:
        with connection.cursor() as cursor:
            # Check if user already exists
            cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
            if cursor.fetchone():
                return False
            
            # Hash password with salt
            password_hash, salt = hash_password(password)
            
            # Insert new user
            cursor.execute(
                "INSERT INTO users (username, password_hash, salt) VALUES (%s, %s, %s)",
                (username, password_hash, salt)
            )
        connection.commit()
        return True
    except Exception as e:
        connection.rollback()
        print(f"Error registering user: {e}")
        raise
    finally:
        connection.close()


def authenticate_user(username: str, password: str) -> bool:
    """
    Authenticate a user by verifying their password.
    
    Args:
        username: Username
        password: Plain text password
    
    Returns:
        True if authentication succeeds, False otherwise
    """
    connection = get_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT password_hash, salt FROM users WHERE username = %s",
                (username,)
            )
            result = cursor.fetchone()
            
            if not result:
                return False
            
            stored_hash = result["password_hash"]
            stored_salt = result["salt"]
            
            return verify_password(password, stored_hash, stored_salt)
    except Exception as e:
        print(f"Error authenticating user: {e}")
        raise
    finally:
        connection.close()


def user_exists(username: str) -> bool:
    """
    Check if a user exists in the database.
    
    Args:
        username: Username to check
    
    Returns:
        True if user exists, False otherwise
    """
    connection = get_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
            return cursor.fetchone() is not None
    finally:
        connection.close()


def main():
    """Main entry point for the db module."""
    parser = argparse.ArgumentParser(description="Database management for SecureChat")
    parser.add_argument(
        "--init",
        action="store_true",
        help="Initialize the database by creating the users table"
    )
    args = parser.parse_args()
    
    if args.init:
        init_db()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()