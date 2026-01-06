from fastapi.testclient import TestClient
from src.app import app

client = TestClient(app)


def test_login_and_protected_unregistration():
    # Student login
    r = client.post("/auth/token", data={"username": "student", "password": "studentpass"})
    assert r.status_code == 200
    token_student = r.json()["access_token"]

    # Student should be forbidden from unregistering
    r2 = client.delete(
        "/activities/Chess Club/unregister",
        params={"email": "michael@mergington.edu"},
        headers={"Authorization": f"Bearer {token_student}"},
    )
    assert r2.status_code == 403

    # Admin login
    r = client.post("/auth/token", data={"username": "admin", "password": "adminpass"})
    assert r.status_code == 200
    token_admin = r.json()["access_token"]

    # Admin can unregister
    r3 = client.delete(
        "/activities/Chess Club/unregister",
        params={"email": "michael@mergington.edu"},
        headers={"Authorization": f"Bearer {token_admin}"},
    )
    assert r3.status_code == 200
    assert "Unregistered michael@mergington.edu" in r3.json()["message"]
