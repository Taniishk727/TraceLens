"""
============================================================
TraceLens Hash Module Unit Tests
============================================================

Unit tests for Hash Input Validation, Hash Algorithm Identification,
Ambiguity Handling, Signature Matching, and API Routes.

Author:
    TraceLens
"""

import pytest
from app.osint.modules.hash.validator import HashValidator
from app.osint.modules.hash.detector import HashDetector
from app.osint.modules.hash.engine import HashEngine, investigate
from app.osint.engine import investigate as core_investigate
from app import create_app


@pytest.fixture
def app():
    app = create_app()
    app.config["TESTING"] = True
    return app


@pytest.fixture
def client(app):
    return app.test_client()


# ==========================================================
# 1. INPUT VALIDATION TESTS
# ==========================================================

def test_validator_empty_and_whitespace():
    res_empty = HashValidator.validate("")
    assert not res_empty.valid
    assert res_empty.error is not None

    res_ws = HashValidator.validate("   \n\t  ")
    assert not res_ws.valid
    assert res_ws.error is not None

    res_none = HashValidator.validate(None)
    assert not res_none.valid


def test_validator_whitespace_trimming():
    raw = " 5f4dcc3b5aa765d61d8327deb882cf99 "
    res = HashValidator.validate(raw)
    assert res.valid
    assert res.input == raw
    assert res.normalized == "5f4dcc3b5aa765d61d8327deb882cf99"
    assert res.length == 32


def test_validator_internal_whitespace():
    res = HashValidator.validate("5f4dcc3b 5aa765d61d8327deb882cf99")
    assert not res.valid
    assert "internal whitespace" in res.error.lower()


def test_validator_invalid_characters():
    res = HashValidator.validate("5f4dcc3b5aa765d61d8327deb882cf9g")  # 'g' is invalid hex in 32-char hex format
    assert not res.valid
    assert "invalid" in res.error.lower()


def test_validator_case_normalization():
    upper_hex = "5F4DCC3B5AA765D61D8327DEB882CF99"
    res_upper = HashValidator.validate(upper_hex)
    assert res_upper.valid
    assert res_upper.input == upper_hex
    assert res_upper.normalized == "5f4dcc3b5aa765d61d8327deb882cf99"

    mixed_hex = "5f4dcc3B5aa765D61d8327deb882cf99"
    res_mixed = HashValidator.validate(mixed_hex)
    assert res_mixed.valid
    assert res_mixed.normalized == "5f4dcc3b5aa765d61d8327deb882cf99"


# ==========================================================
# 2. HASH IDENTIFICATION & ALGORITHM TESTS
# ==========================================================

def test_detect_md5_ambiguous():
    """32 hex characters must return AMBIGUOUS confidence and list MD5, MD4, NTLM, etc."""
    md5_hash = "5f4dcc3b5aa765d61d8327deb882cf99"
    res = investigate(md5_hash)
    assert res["valid"]
    assert res["status"] == "ambiguous"
    assert res["confidence"] == "ambiguous"
    assert "MD5" in res["possible_types"]
    assert "MD4" in res["possible_types"]
    assert "NTLM" in res["possible_types"]
    assert len(res["possible_types"]) >= 3


def test_detect_sha1():
    sha1_hash = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    res = investigate(sha1_hash)
    assert res["valid"]
    assert res["length"] == 40
    assert "SHA-1" in res["possible_types"]


def test_detect_sha256():
    sha256_hash = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    res = investigate(sha256_hash)
    assert res["valid"]
    assert res["length"] == 64
    assert "SHA-256" in res["possible_types"]


def test_detect_sha512():
    sha512_hash = (
        "b109f3bbbc244eb82441917ed06d618b9008dd09b1bece9f1d6f7b4d6f1f7ee4"
        "ce8099cf179646c61d8b9e696d744ec1c5453e983416e09919cf628f8045d943"
    )
    res = investigate(sha512_hash)
    assert res["valid"]
    assert res["length"] == 128
    assert res["hash_type"] == "SHA-512"
    assert res["possible_types"] == ["SHA-512"]
    assert res["status"] == "identified"


def test_detect_bcrypt_structured():
    bcrypt_hash = "$2b$12$e80iA.a210.0210.0210.e80iA.a210.0210.0210.e80iA.a2101"
    res = investigate(bcrypt_hash)
    assert res["valid"]
    assert res["status"] == "identified"
    assert res["confidence"] == "confirmed"
    assert res["hash_type"] == "bcrypt"
    assert res["possible_types"] == ["bcrypt"]


def test_detect_argon2_structured():
    argon2_hash = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$R29vZGJ5ZSBXb3JsZA"
    res = investigate(argon2_hash)
    assert res["valid"]
    assert res["status"] == "identified"
    assert res["confidence"] == "confirmed"
    assert res["hash_type"] == "Argon2"


def test_detect_random_text():
    res = investigate("this is definitely not a valid hash string!")
    assert not res["valid"]
    assert res["status"] == "invalid"


# ==========================================================
# 3. CORE ENGINE INTEGRATION TESTS
# ==========================================================

def test_core_engine_auto_detection():
    res = core_investigate("5f4dcc3b5aa765d61d8327deb882cf99")
    assert res["success"]
    assert res["type"] == "hash"
    assert res["data"]["status"] == "ambiguous"
    assert "MD5" in res["data"]["possible_types"]


def test_core_engine_override():
    res = core_investigate("5f4dcc3b5aa765d61d8327deb882cf99", forced_type="hash")
    assert res["success"]
    assert res["override"]
    assert res["type"] == "hash"


# ==========================================================
# 4. API ENDPOINT TESTS
# ==========================================================

def test_api_hash_investigate_valid(client):
    response = client.post(
        "/api/hash/investigate",
        json={"hash": "5f4dcc3b5aa765d61d8327deb882cf99"},
    )
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"]
    assert data["status"] == "ambiguous"
    assert data["confidence"] == "ambiguous"
    assert "MD5" in data["possible_types"]
    assert "MD4" in data["possible_types"]
    assert "NTLM" in data["possible_types"]
    assert data["length"] == 32
    assert data["encoding"] == "Hexadecimal"


def test_api_hash_investigate_invalid(client):
    response = client.post(
        "/api/hash/investigate",
        json={"hash": "invalid hash string with spaces!"},
    )
    assert response.status_code == 400
    data = response.get_json()
    assert not data["success"]
    assert data["status"] == "invalid"
