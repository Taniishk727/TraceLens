"""
============================================================
TraceLens Hash Module - Algorithm Signature Database
============================================================

Maintainable, structured database of hash algorithm definitions.
Defines parameters for pattern matching, exact prefix detection,
length/character-set matching, and candidate category classification.

Author:
    TraceLens
"""

import re
from typing import Any, Dict, List, Optional


ALGORITHM_DEFINITIONS: List[Dict[str, Any]] = [
    # ------------------------------------------------------
    # 32 Hexadecimal Characters (Length 32)
    # ------------------------------------------------------
    {
        "name": "MD5",
        "aliases": ["MD5sum"],
        "length": 32,
        "charset": "hex",
        "encoding": "Hexadecimal",
        "pattern": re.compile(r"^[a-fA-F0-9]{32}$"),
        "prefix": None,
        "category": "Cryptographic Hash",
        "description": "Message Digest Algorithm 5 (128-bit output)",
        "is_structured": False,
    },
    {
        "name": "MD4",
        "aliases": ["MD4sum"],
        "length": 32,
        "charset": "hex",
        "encoding": "Hexadecimal",
        "pattern": re.compile(r"^[a-fA-F0-9]{32}$"),
        "prefix": None,
        "category": "Cryptographic Hash",
        "description": "Message Digest Algorithm 4 (128-bit output)",
        "is_structured": False,
    },
    {
        "name": "NTLM",
        "aliases": ["NT Hash"],
        "length": 32,
        "charset": "hex",
        "encoding": "Hexadecimal",
        "pattern": re.compile(r"^[a-fA-F0-9]{32}$"),
        "prefix": None,
        "category": "Windows Password Hash",
        "description": "NT LAN Manager hash (MD4 of UTF-16LE password)",
        "is_structured": False,
    },
    {
        "name": "RIPEMD-128",
        "aliases": ["RMD-128"],
        "length": 32,
        "charset": "hex",
        "encoding": "Hexadecimal",
        "pattern": re.compile(r"^[a-fA-F0-9]{32}$"),
        "prefix": None,
        "category": "Cryptographic Hash",
        "description": "RACE Integrity Primitives Evaluation Message Digest 128-bit",
        "is_structured": False,
    },
    {
        "name": "LM",
        "aliases": ["LANMAN"],
        "length": 32,
        "charset": "hex",
        "encoding": "Hexadecimal",
        "pattern": re.compile(r"^[a-fA-F0-9]{32}$"),
        "prefix": None,
        "category": "Legacy Windows Hash",
        "description": "LAN Manager Hash",
        "is_structured": False,
    },

    # ------------------------------------------------------
    # 40 Hexadecimal Characters (Length 40)
    # ------------------------------------------------------
    {
        "name": "SHA-1",
        "aliases": ["SHA1"],
        "length": 40,
        "charset": "hex",
        "encoding": "Hexadecimal",
        "pattern": re.compile(r"^[a-fA-F0-9]{40}$"),
        "prefix": None,
        "category": "Cryptographic Hash",
        "description": "Secure Hash Algorithm 1 (160-bit output)",
        "is_structured": False,
    },
    {
        "name": "RIPEMD-160",
        "aliases": ["RMD-160"],
        "length": 40,
        "charset": "hex",
        "encoding": "Hexadecimal",
        "pattern": re.compile(r"^[a-fA-F0-9]{40}$"),
        "prefix": None,
        "category": "Cryptographic Hash",
        "description": "RACE Integrity Primitives Evaluation Message Digest 160-bit",
        "is_structured": False,
    },

    # ------------------------------------------------------
    # 56 Hexadecimal Characters (Length 56)
    # ------------------------------------------------------
    {
        "name": "SHA-224",
        "aliases": ["SHA224"],
        "length": 56,
        "charset": "hex",
        "encoding": "Hexadecimal",
        "pattern": re.compile(r"^[a-fA-F0-9]{56}$"),
        "prefix": None,
        "category": "Cryptographic Hash (SHA-2)",
        "description": "Secure Hash Algorithm 2 (224-bit truncated output)",
        "is_structured": False,
    },
    {
        "name": "SHA-512/224",
        "aliases": ["SHA512/224"],
        "length": 56,
        "charset": "hex",
        "encoding": "Hexadecimal",
        "pattern": re.compile(r"^[a-fA-F0-9]{56}$"),
        "prefix": None,
        "category": "Cryptographic Hash (SHA-2)",
        "description": "SHA-512 truncated to 224 bits with alternative initial state",
        "is_structured": False,
    },

    # ------------------------------------------------------
    # 64 Hexadecimal Characters (Length 64)
    # ------------------------------------------------------
    {
        "name": "SHA-256",
        "aliases": ["SHA256"],
        "length": 64,
        "charset": "hex",
        "encoding": "Hexadecimal",
        "pattern": re.compile(r"^[a-fA-F0-9]{64}$"),
        "prefix": None,
        "category": "Cryptographic Hash (SHA-2)",
        "description": "Secure Hash Algorithm 2 (256-bit output)",
        "is_structured": False,
    },
    {
        "name": "SHA-512/256",
        "aliases": ["SHA512/256"],
        "length": 64,
        "charset": "hex",
        "encoding": "Hexadecimal",
        "pattern": re.compile(r"^[a-fA-F0-9]{64}$"),
        "prefix": None,
        "category": "Cryptographic Hash (SHA-2)",
        "description": "SHA-512 truncated to 256 bits with alternative initial state",
        "is_structured": False,
    },
    {
        "name": "RIPEMD-256",
        "aliases": ["RMD-256"],
        "length": 64,
        "charset": "hex",
        "encoding": "Hexadecimal",
        "pattern": re.compile(r"^[a-fA-F0-9]{64}$"),
        "prefix": None,
        "category": "Cryptographic Hash",
        "description": "RACE Integrity Primitives Evaluation Message Digest 256-bit",
        "is_structured": False,
    },

    # ------------------------------------------------------
    # 80 Hexadecimal Characters (Length 80)
    # ------------------------------------------------------
    {
        "name": "RIPEMD-320",
        "aliases": ["RMD-320"],
        "length": 80,
        "charset": "hex",
        "encoding": "Hexadecimal",
        "pattern": re.compile(r"^[a-fA-F0-9]{80}$"),
        "prefix": None,
        "category": "Cryptographic Hash",
        "description": "RACE Integrity Primitives Evaluation Message Digest 320-bit",
        "is_structured": False,
    },

    # ------------------------------------------------------
    # 96 Hexadecimal Characters (Length 96)
    # ------------------------------------------------------
    {
        "name": "SHA-384",
        "aliases": ["SHA384"],
        "length": 96,
        "charset": "hex",
        "encoding": "Hexadecimal",
        "pattern": re.compile(r"^[a-fA-F0-9]{96}$"),
        "prefix": None,
        "category": "Cryptographic Hash (SHA-2)",
        "description": "Secure Hash Algorithm 2 (384-bit output)",
        "is_structured": False,
    },

    # ------------------------------------------------------
    # 128 Hexadecimal Characters (Length 128)
    # ------------------------------------------------------
    {
        "name": "SHA-512",
        "aliases": ["SHA512"],
        "length": 128,
        "charset": "hex",
        "encoding": "Hexadecimal",
        "pattern": re.compile(r"^[a-fA-F0-9]{128}$"),
        "prefix": None,
        "category": "Cryptographic Hash (SHA-2)",
        "description": "Secure Hash Algorithm 2 (512-bit output)",
        "is_structured": False,
    },

    # ------------------------------------------------------
    # Structured Hash Formats (Signature / Prefix Based)
    # ------------------------------------------------------
    {
        "name": "bcrypt",
        "aliases": ["Blowfish Crypt"],
        "length": 60,
        "charset": "custom_base64",
        "encoding": "Modular Crypt Format",
        "pattern": re.compile(r"^\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}$"),
        "prefix": "$2",
        "category": "Key Derivation / Password Hash",
        "description": "Blowfish-based adaptive hashing algorithm",
        "is_structured": True,
    },
    {
        "name": "Argon2id",
        "aliases": ["Argon2"],
        "length": None,
        "charset": "custom_base64",
        "encoding": "Modular Crypt Format",
        "pattern": re.compile(r"^\$argon2id\$(v=\d+\$)?m=\d+,t=\d+,p=\d+\$[./A-Za-z0-9+/=]+\$[./A-Za-z0-9+/=]+$"),
        "prefix": "$argon2id$",
        "category": "Key Derivation / Password Hash",
        "description": "Password Hashing Competition (PHC) winner (hybrid mode)",
        "is_structured": True,
    },
    {
        "name": "Argon2i",
        "aliases": ["Argon2"],
        "length": None,
        "charset": "custom_base64",
        "encoding": "Modular Crypt Format",
        "pattern": re.compile(r"^\$argon2i\$(v=\d+\$)?m=\d+,t=\d+,p=\d+\$[./A-Za-z0-9+/=]+\$[./A-Za-z0-9+/=]+$"),
        "prefix": "$argon2i$",
        "category": "Key Derivation / Password Hash",
        "description": "Password Hashing Competition (PHC) winner (side-channel resistant)",
        "is_structured": True,
    },
    {
        "name": "Argon2d",
        "aliases": ["Argon2"],
        "length": None,
        "charset": "custom_base64",
        "encoding": "Modular Crypt Format",
        "pattern": re.compile(r"^\$argon2d\$(v=\d+\$)?m=\d+,t=\d+,p=\d+\$[./A-Za-z0-9+/=]+\$[./A-Za-z0-9+/=]+$"),
        "prefix": "$argon2d$",
        "category": "Key Derivation / Password Hash",
        "description": "Password Hashing Competition (PHC) winner (GPU resistant)",
        "is_structured": True,
    },
    {
        "name": "Unix MD5 Crypt",
        "aliases": ["MD5 Crypt", "glibc MD5"],
        "length": None,
        "charset": "custom_base64",
        "encoding": "Modular Crypt Format",
        "pattern": re.compile(r"^\$1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}$"),
        "prefix": "$1$",
        "category": "Unix Password Hash",
        "description": "Unix standard MD5-based password hash",
        "is_structured": True,
    },
    {
        "name": "SHA-256 Crypt",
        "aliases": ["glibc SHA-256 Crypt"],
        "length": None,
        "charset": "custom_base64",
        "encoding": "Modular Crypt Format",
        "pattern": re.compile(r"^\$5\$(rounds=\d+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43}$"),
        "prefix": "$5$",
        "category": "Unix Password Hash",
        "description": "glibc SHA-256 adaptive password hash",
        "is_structured": True,
    },
    {
        "name": "SHA-512 Crypt",
        "aliases": ["glibc SHA-512 Crypt"],
        "length": None,
        "charset": "custom_base64",
        "encoding": "Modular Crypt Format",
        "pattern": re.compile(r"^\$6\$(rounds=\d+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}$"),
        "prefix": "$6$",
        "category": "Unix Password Hash",
        "description": "glibc SHA-512 adaptive password hash",
        "is_structured": True,
    },
    {
        "name": "Apache APR1 Crypt",
        "aliases": ["APR1 MD5"],
        "length": None,
        "charset": "custom_base64",
        "encoding": "Modular Crypt Format",
        "pattern": re.compile(r"^\$apr1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}$"),
        "prefix": "$apr1$",
        "category": "Apache Password Hash",
        "description": "Apache APR algorithm (variant of MD5 Crypt)",
        "is_structured": True,
    },
    {
        "name": "WordPress / PHPass",
        "aliases": ["PHPass", "phpBB3"],
        "length": 34,
        "charset": "custom_base64",
        "encoding": "PHPass Format",
        "pattern": re.compile(r"^\$[PH]\$[./A-Za-z0-9]{31}$"),
        "prefix": "$P$",
        "category": "CMS Password Hash",
        "description": "PHPass portable hash used in WordPress and phpBB3",
        "is_structured": True,
    },
    {
        "name": "MySQL 4.1+",
        "aliases": ["MySQL5", "MySQL SHA-1"],
        "length": 41,
        "charset": "hex",
        "encoding": "MySQL Format",
        "pattern": re.compile(r"^\*[a-fA-F0-9]{40}$"),
        "prefix": "*",
        "category": "Database Password Hash",
        "description": "MySQL 4.1+ double SHA-1 password hash",
        "is_structured": True,
    },
    {
        "name": "MySQL 3.23",
        "aliases": ["MySQL323"],
        "length": 16,
        "charset": "hex",
        "encoding": "Hexadecimal",
        "pattern": re.compile(r"^[a-fA-F0-9]{16}$"),
        "prefix": None,
        "category": "Database Password Hash",
        "description": "Legacy MySQL 3.23 password hash",
        "is_structured": False,
    },
]
