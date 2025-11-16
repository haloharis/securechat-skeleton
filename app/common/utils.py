"""Helper signatures: now_ms, b64e, b64d, sha256_hex."""

import time
import base64
import hashlib


def now_ms() -> int:
    """
    Get current timestamp in milliseconds since Unix epoch.
    
    Returns:
        Current timestamp in milliseconds
    """
    return int(time.time() * 1000)


def b64e(b: bytes) -> str:
    """
    Encode bytes to base64 string.
    
    Args:
        b: Bytes to encode
    
    Returns:
        Base64 encoded string
    """
    return base64.b64encode(b).decode("utf-8")


def b64d(s: str) -> bytes:
    """
    Decode base64 string to bytes.
    
    Args:
        s: Base64 encoded string
    
    Returns:
        Decoded bytes
    """
    return base64.b64decode(s.encode("utf-8"))


def sha256_hex(data: bytes) -> str:
    """
    Compute SHA-256 hash of data and return as hexadecimal string.
    
    Args:
        data: Data to hash
    
    Returns:
        SHA-256 hash as hexadecimal string
    """
    return hashlib.sha256(data).hexdigest()
