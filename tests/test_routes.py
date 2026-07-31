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
