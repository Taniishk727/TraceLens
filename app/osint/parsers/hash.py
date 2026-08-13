from app.osint.modules.hash.engine import investigate as hash_investigate


def investigate(target):
    return hash_investigate(target)