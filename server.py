import time
import uuid
from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import jwt

# --- Configuration ---
JWT_ALGORITHM = "RS256"
JWT_EXP_SECONDS = 300       # JWT lifetime in seconds (5 minutes)
KEY_EXPIRY_SECONDS = 600    # Key lifetime in seconds (10 minutes)

app = FastAPI(title="JWKS Server")

# --- Key Management ---
class KeyPair:
    """Represents an RSA key pair with a kid and expiry"""
    def __init__(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
        self.kid = str(uuid.uuid4())
        self.created_at = time.time()
        self.expiry = self.created_at + KEY_EXPIRY_SECONDS

    def to_jwk(self):
        """Convert the public key to JWKS format"""
        numbers = self.public_key.public_numbers()
        return {
            "kty": "RSA",
            "kid": self.kid,
            "use": "sig",
            "alg": JWT_ALGORITHM,
            "n": int_to_base64(numbers.n),
            "e": int_to_base64(numbers.e),
        }

# In-memory store for keys
keys = {}

# --- Utilities ---
def int_to_base64(n: int) -> str:
    """Encode integer to base64url without padding"""
    import base64
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")

def cleanup_keys():
    """Remove expired keys from the store"""
    now = time.time()
    for kid in list(keys.keys()):
        if keys[kid].expiry < now:
            del keys[kid]

def get_active_keys():
    cleanup_keys()
    return list(keys.values())

def get_expired_keys():
    """Return keys that have expired (for issuing expired JWTs)"""
    now = time.time()
    return [k for k in keys.values() if k.expiry < now]

def sign_jwt(key: KeyPair, expired: bool = False) -> str:
    """Sign a JWT with the given key"""
    now = int(time.time())
    exp = now + JWT_EXP_SECONDS
    if expired:
        # Force the JWT to be expired
        exp = now - 10  # 10 seconds in the past
    payload = {
        "sub": "mock_user",
        "iat": now,
        "exp": exp,
        "kid": key.kid
    }
    private_bytes = key.private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return jwt.encode(payload, private_bytes, algorithm=JWT_ALGORITHM)

# --- Endpoints ---
@app.get("/.well-known/jwks.json")
def jwks():
    """Return all active keys in JWKS format"""
    active = get_active_keys()
    return JSONResponse({"keys": [k.to_jwk() for k in active]})

@app.post("/auth")
def auth(expired: bool = Query(False)):
    """
    Issue JWT.
    If 'expired=true', issue a JWT that is already expired.
    """
    key_pool = get_active_keys() if not expired else get_expired_keys()
    if not key_pool:
        # If no keys available, generate one
        k = KeyPair()
        keys[k.kid] = k
        key_pool = [k]
    token = sign_jwt(key_pool[0], expired=expired)
    return {"access_token": token, "token_type": "bearer"}

# --- Initialize keys on startup ---
def generate_initial_keys(count: int = 2):
    for _ in range(count):
        k = KeyPair()
        keys[k.kid] = k

generate_initial_keys()

