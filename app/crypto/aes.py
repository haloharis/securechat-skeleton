"""AES-128(ECB)+PKCS#7 helpers (use library)."""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


def encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt plaintext using AES-128 in ECB mode with PKCS#7 padding.
    
    Args:
        key: 16-byte AES key
        plaintext: Plaintext to encrypt
    
    Returns:
        Encrypted ciphertext
    """
    if len(key) != 16:
        raise ValueError("AES-128 requires a 16-byte key")
    
    # Create cipher with AES-128 ECB mode
    cipher = Cipher(
        algorithms.AES(key),
        modes.ECB(),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    
    # Apply PKCS#7 padding
    padder = padding.PKCS7(128).padder()  # 128 bits = 16 bytes block size
    padded_data = padder.update(plaintext)
    padded_data += padder.finalize()
    
    # Encrypt the padded data
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    return ciphertext


def decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt ciphertext using AES-128 in ECB mode with PKCS#7 padding.
    
    Args:
        key: 16-byte AES key
        ciphertext: Encrypted ciphertext to decrypt
    
    Returns:
        Decrypted plaintext (with padding removed)
    """
    if len(key) != 16:
        raise ValueError("AES-128 requires a 16-byte key")
    
    # Create cipher with AES-128 ECB mode
    cipher = Cipher(
        algorithms.AES(key),
        modes.ECB(),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    
    # Decrypt the ciphertext
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove PKCS#7 padding
    unpadder = padding.PKCS7(128).unpadder()  # 128 bits = 16 bytes block size
    plaintext = unpadder.update(padded_plaintext)
    plaintext += unpadder.finalize()
    
    return plaintext
