import httpx
import time
import jwt
import pytest

BASE_URL = "http://localhost:8080"

@pytest.fixture(scope="module")
def client():
    with httpx.Client(base_url=BASE_URL) as c:
        yield c

def test_jwks_endpoint(client):
    r = client.get("/.well-known/jwks.json")
    assert r.status_code == 200
    assert "keys" in r.json()
    assert len(r.json()["keys"]) > 0

def test_auth_endpoint(client):
    r = client.post("/auth")
    token = r.json()["access_token"]
    payload = jwt.decode(token, options={"verify_signature": False})
    assert payload["sub"] == "mock_user"

def test_auth_expired_key(client):
    r = client.post("/auth?expired=true")
    token = r.json()["access_token"]
    payload = jwt.decode(token, options={"verify_signature": False})
    assert payload["exp"] <= int(time.time())

