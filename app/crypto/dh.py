"""Classic DH helpers + Trunc16(SHA256(Ks)) derivation."""

import hashlib
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


# Standard DH parameters (RFC 5114, 2048-bit MODP Group)
# Using pre-defined parameters for Classic DH
def get_dh_parameters():
    """
    Get standard DH parameters (2048-bit MODP Group).
    
    Returns:
        DHParameters object
    """
    # Using RFC 5114 2048-bit MODP Group
    # These are standard, well-known parameters
    p = int(
        "0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
        "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
        "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
        "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
        "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
        "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
        "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
        16
    )
    g = 2
    
    parameter_numbers = dh.DHParameterNumbers(p, g)
    return parameter_numbers.parameters(default_backend())


def generate_dh_private_key():
    """
    Generate a private key for Diffie-Hellman key exchange.
    
    Returns:
        DHPrivateKey object
    """
    parameters = get_dh_parameters()
    return parameters.generate_private_key()


def get_dh_public_key(private_key) -> bytes:
    """
    Get the public key from a DH private key.
    
    Args:
        private_key: DHPrivateKey object
    
    Returns:
        Public key as PEM-encoded bytes
    """
    public_key = private_key.public_key()
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def load_dh_public_key(public_key_bytes: bytes):
    """
    Load a DH public key from PEM-encoded bytes.
    
    Args:
        public_key_bytes: PEM-encoded public key bytes
    
    Returns:
        DHPublicKey object
    """
    return serialization.load_pem_public_key(
        public_key_bytes,
        backend=default_backend()
    )


def derive_shared_secret(private_key, peer_public_key) -> bytes:
    """
    Derive the shared secret using Diffie-Hellman key exchange.
    
    Args:
        private_key: Our DHPrivateKey object
        peer_public_key: Peer's DHPublicKey object
    
    Returns:
        Shared secret Ks as bytes
    """
    shared_secret = private_key.exchange(peer_public_key)
    return shared_secret


def derive_aes_key(shared_secret: bytes) -> bytes:
    """
    Derive a 16-byte AES key from the shared secret using Trunc16(SHA256(Ks)).
    
    Args:
        shared_secret: Shared secret Ks from DH exchange
    
    Returns:
        16-byte AES key (first 16 bytes of SHA256(shared_secret))
    """
    # Compute SHA-256 of the shared secret
    hash_value = hashlib.sha256(shared_secret).digest()
    
    # Truncate to 16 bytes for AES-128
    aes_key = hash_value[:16]
    
    return aes_key
