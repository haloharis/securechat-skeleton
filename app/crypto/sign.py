"""RSA PKCS#1 v1.5 SHA-256 sign/verify."""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend


def sign(private_key, data: bytes) -> bytes:
    """
    Sign data using RSA PKCS#1 v1.5 with SHA-256.
    
    Args:
        private_key: RSA private key (RSAPrivateKey object or PEM bytes)
        data: Data to sign
    
    Returns:
        Signature as bytes
    """
    # If private_key is bytes, load it
    if isinstance(private_key, bytes):
        private_key = serialization.load_pem_private_key(
            private_key,
            password=None,
            backend=default_backend()
        )
    
    # Sign using PKCS#1 v1.5 padding with SHA-256
    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    
    return signature


def verify(public_key, data: bytes, signature: bytes) -> bool:
    """
    Verify a signature using RSA PKCS#1 v1.5 with SHA-256.
    
    Args:
        public_key: RSA public key (RSAPublicKey object, certificate, or PEM bytes)
        data: Original data that was signed
        signature: Signature to verify
    
    Returns:
        True if signature is valid, False otherwise
    
    Raises:
        InvalidSignature: If signature verification fails
    """
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    
    # If public_key is bytes, try to load as certificate first, then as public key
    if isinstance(public_key, bytes):
        try:
            # Try loading as X.509 certificate
            cert = x509.load_pem_x509_certificate(public_key, default_backend())
            public_key = cert.public_key()
        except Exception:
            # If not a certificate, try loading as public key
            public_key = serialization.load_pem_public_key(
                public_key,
                backend=default_backend()
            )
    
    # If it's a certificate object, extract public key
    if hasattr(public_key, 'public_key'):
        public_key = public_key.public_key()
    
    try:
        # Verify signature using PKCS#1 v1.5 padding with SHA-256
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
