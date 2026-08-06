"""
============================================================
TraceLens Flask Routes Integration Tests
============================================================

Tests for Flask routes (/search, /override) handling both Username
and Email target investigations.

Run:
    pytest tests/test_routes.py -v
"""

import pytest
from app import create_app


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_home_route(client):
    rv = client.get("/")
    assert rv.status_code == 200


def test_search_get_route(client):
    rv = client.get("/search")
    assert rv.status_code == 200
    assert b"OSINT Investigation" in rv.data


def test_search_post_email_valid(client):
    rv = client.post("/search", data={"query": "testuser@gmail.com"})
    assert rv.status_code == 200
    assert b"Investigation Results" in rv.data
    assert b"testuser@gmail.com" in rv.data
    assert b"Google Workspace / Gmail" in rv.data
    assert b"Email Collectors Pipeline" in rv.data


def test_search_post_email_invalid(client):
    rv = client.post("/search", data={"query": "user@invalid"})
    assert rv.status_code == 200
    assert b"Target Validation Failed" in rv.data
    assert b"Email" in rv.data


def test_search_post_username(client):
    rv = client.post("/search", data={"query": "torvalds"})
    assert rv.status_code == 200
    assert b"Investigation Results" in rv.data
    assert b"torvalds" in rv.data
    assert b"Username Investigation" in rv.data


def test_override_post_email(client):
    rv = client.post(
        "/override", data={"target": "testuser@proton.me", "forced_type": "email"}
    )
    assert rv.status_code == 200
    assert b"Investigation Results" in rv.data
    assert b"testuser@proton.me" in rv.data
    assert b"Proton Mail" in rv.data


def test_email_search_get_route(client):
    rv = client.get("/email-search")
    assert rv.status_code == 200
    assert b"Email Investigation" in rv.data
    assert b"Investigate an email address using OSINT collectors." in rv.data


def test_email_search_post_valid(client):
    rv = client.post("/email-search", data={"email": "investigate@gmail.com"})
    assert rv.status_code == 200
    assert b"Investigation Results" in rv.data
    assert b"investigate@gmail.com" in rv.data


def test_email_search_post_invalid(client):
    rv = client.post("/email-search", data={"email": "invalid--email"})
    assert rv.status_code == 200
    assert b"Email Investigation" in rv.data
    assert b"Invalid email" in rv.data or b"validation" in rv.data.lower()


def test_username_search_route_alias(client):
    rv = client.get("/username-search")
    assert rv.status_code == 200
    assert b"OSINT Investigation" in rv.data

    rv_alt = client.get("/username")
    assert rv_alt.status_code == 200
    assert b"OSINT Investigation" in rv_alt.data


def test_phone_search_get_route(client):
    rv = client.get("/phone-search")
    assert rv.status_code == 200
    assert b"Phone Investigation" in rv.data
    assert b"Investigate phone numbers using OSINT collectors." in rv.data


def test_phone_search_post_valid(client):
    rv = client.post("/phone-search", data={"phone": "+919876543210"})
    assert rv.status_code == 200
    assert b"Investigation Results" in rv.data
    assert b"+919876543210" in rv.data


def test_phone_search_post_invalid(client):
    rv = client.post("/phone-search", data={"phone": "123"})
    assert rv.status_code == 200
    assert b"Phone Investigation" in rv.data
    assert b"Phone number must contain between 7 and 15 digits" in rv.data or b"Invalid" in rv.data




