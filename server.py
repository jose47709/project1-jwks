import time
import uuid
import sqlite3
from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import jwt
import base64

# --- Configuration ---
JWT_ALGORITHM = "RS256"
JWT_EXP_SECONDS = 300       # JWT lifetime in seconds (5 minutes)
KEY_EXPIRY_SECONDS = 3600   # Key lifetime in seconds (1 hour)
DB_FILE = "totally_not_my_privateKeys.db"

app = FastAPI(title="JWKS Server with SQLite")

# --- Utilities ---
def int_to_base64(n: int) -> str:
    """Encode integer to base64url without padding"""
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")

def serialize_private_key(private_key) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

def deserialize_private_key(pem_bytes: bytes):
    return serialization.load_pem_private_key(pem_bytes, password=None)

# --- Database Setup ---
def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    with conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS keys(
            kid TEXT PRIMARY KEY,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
        """)
    conn.close()

def insert_key(private_key, expiry_seconds=KEY_EXPIRY_SECONDS):
    conn = get_db()
    kid = str(uuid.uuid4())
    pem = serialize_private_key(private_key)
    exp = int(time.time()) + expiry_seconds
    with conn:
        conn.execute(
            "INSERT INTO keys(kid, key, exp) VALUES (?, ?, ?)",
            (kid, pem, exp)
        )
    conn.close()
    return kid, private_key

def get_keys(expired: bool = False):
    """Return keys from DB filtered by expiry"""
    conn = get_db()
    now = int(time.time())
    query = "SELECT * FROM keys WHERE exp <= ?" if expired else "SELECT * FROM keys WHERE exp > ?"
    cur = conn.execute(query, (now,))
    rows = cur.fetchall()
    conn.close()
    return rows

# --- Key Generation ---
def generate_initial_keys():
    # Ensure at least one expired key and one active key
    conn = get_db()
    cur = conn.execute("SELECT COUNT(*) as count FROM keys")
    count = cur.fetchone()["count"]
    conn.close()
    if count == 0:
        # Expired key
        expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        insert_key(expired_key, expiry_seconds=-10)  # expired 10 seconds ago
        # Active key
        active_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        insert_key(active_key, expiry_seconds=KEY_EXPIRY_SECONDS)

# --- JWT Signing ---
def sign_jwt(private_key, kid, expired: bool = False):
    now = int(time.time())
    exp = now + JWT_EXP_SECONDS
    if expired:
        exp = now - 10  # force expired JWT
    payload = {
        "sub": "mock_user",
        "iat": now,
        "exp": exp,
        "kid": kid
    }
    pem_bytes = serialize_private_key(private_key)
    return jwt.encode(payload, pem_bytes, algorithm=JWT_ALGORITHM)

# --- Endpoints ---
@app.get("/.well-known/jwks.json")
def jwks():
    active_keys = get_keys(expired=False)
    jwks_keys = []
    for row in active_keys:
        private_key = deserialize_private_key(row["key"])
        public_numbers = private_key.public_key().public_numbers()
        jwks_keys.append({
            "kty": "RSA",
            "kid": row["kid"],
            "use": "sig",
            "alg": JWT_ALGORITHM,
            "n": int_to_base64(public_numbers.n),
            "e": int_to_base64(public_numbers.e)
        })
    return JSONResponse({"keys": jwks_keys})

@app.post("/auth")
def auth(expired: bool = Query(False)):
    keys_db = get_keys(expired=expired)
    if not keys_db:
        # No keys of requested type, generate one
        new_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        kid, new_key = insert_key(new_key, expiry_seconds=KEY_EXPIRY_SECONDS if not expired else -10)
        private_key = new_key
    else:
        row = keys_db[0]
        private_key = deserialize_private_key(row["key"])
        kid = row["kid"]
    token = sign_jwt(private_key, kid, expired=expired)
    return {"access_token": token, "token_type": "bearer"}

# --- Startup ---
init_db()
generate_initial_keys()
        

