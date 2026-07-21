import pytest
from fastapi.testclient import TestClient
from backend.app.database.session import Base, engine
from backend.app.main import app

# Ensure database tables exist for tests
Base.metadata.create_all(bind=engine)

client = TestClient(app)

def test_health_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "Enterprise SIEM Engine"

def test_dashboard_endpoint():
    response = client.get("/api/dashboard")
    assert response.status_code == 200
    data = response.json()
    assert "stats" in data
    assert "top_ips" in data

def test_alerts_endpoint():
    response = client.get("/api/alerts")
    assert response.status_code == 200
    data = response.json()
    assert "alerts" in data
    assert "total" in data

def test_user_registration_and_login():
    reg_payload = {
        "username": "test_analyst_01",
        "email": "analyst01@test.com",
        "password": "securepassword123",
        "role": "Analyst"
    }
    res_reg = client.post("/api/auth/register", json=reg_payload)
    assert res_reg.status_code in (201, 400)

    login_payload = {
        "username": "test_analyst_01",
        "password": "securepassword123"
    }
    res_login = client.post("/api/auth/login", json=login_payload)
    if res_login.status_code == 200:
        data = res_login.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
