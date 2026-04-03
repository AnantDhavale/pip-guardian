import hashlib
from pathlib import Path


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def verify_sha256(path: Path, expected_sha256: str) -> bool:
    if not expected_sha256:
        return False
    actual = sha256_file(path)
    return actual.lower() == expected_sha256.lower()
