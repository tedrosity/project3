import sqlite3
import datetime
from cryptography.hazmat.primitives.asymmetric import rsa
from utils import serialize_key, deserialize_private_key, encrypt_data, decrypt_data
from argon2 import PasswordHasher

DB_FILE = "totally_not_my_privateKeys.db"
db = sqlite3.connect(DB_FILE, check_same_thread=False)
cursor = db.cursor()
ph = PasswordHasher()

def init_db():
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS keys(
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    )
    ''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        email TEXT UNIQUE,
        date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP
    )
    ''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS auth_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_ip TEXT NOT NULL,
        request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        user_id INTEGER,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    ''')
    db.commit()

    existing = cursor.execute('SELECT COUNT(*) FROM keys').fetchone()[0]
    if existing == 0:
        generate_initial_keys()

def generate_initial_keys():
    now = datetime.datetime.utcnow()
    expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    save_key(expired_key, int((now - datetime.timedelta(hours=1)).timestamp()))
    valid_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    save_key(valid_key, int((now + datetime.timedelta(hours=1)).timestamp()))

def save_key(private_key, expiry_timestamp):
    pem = serialize_key(private_key)
    encrypted_pem = encrypt_data(pem)
    cursor.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', (encrypted_pem, expiry_timestamp))
    db.commit()

def get_key(expired: bool, now_unix: int):
    if expired:
        row = cursor.execute('SELECT kid, key, exp FROM keys WHERE exp <= ? LIMIT 1', (now_unix,)).fetchone()
    else:
        row = cursor.execute('SELECT kid, key, exp FROM keys WHERE exp > ? LIMIT 1', (now_unix,)).fetchone()
    if row:
        kid, encrypted_key, exp = row
        pem = decrypt_data(encrypted_key)
        return kid, pem, exp
    return None

def get_valid_keys(now_unix: int):
    rows = cursor.execute('SELECT kid, key FROM keys WHERE exp > ?', (now_unix,)).fetchall()
    result = []
    for kid, encrypted_key in rows:
        pem = decrypt_data(encrypted_key)
        result.append((kid, pem))
    return result

def create_user(username: str, email: str, password_plain: str):
    password_hash = ph.hash(password_plain)
    cursor.execute('INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)', (username, password_hash, email))
    db.commit()

def get_user_by_username(username: str):
    return cursor.execute('SELECT id, username, password_hash FROM users WHERE username = ?', (username,)).fetchone()

def log_auth_request(ip: str, user_id: int):
    cursor.execute('INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)', (ip, user_id))
    db.commit()

