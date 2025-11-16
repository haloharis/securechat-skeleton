"""X.509 validation: signed-by-CA, validity window, CN/SAN."""

from datetime import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


class PKIValidationError(Exception):
    """Exception raised when PKI validation fails."""
    pass


def load_ca_certificate(ca_cert_path: str):
    """
    Load the CA certificate from a file.
    
    Args:
        ca_cert_path: Path to CA certificate file (PEM format)
    
    Returns:
        X.509 certificate object
    """
    with open(ca_cert_path, "rb") as f:
        return x509.load_pem_x509_certificate(
            f.read(),
            backend=default_backend()
        )


def load_certificate(cert_data: bytes):
    """
    Load an X.509 certificate from PEM-encoded bytes.
    
    Args:
        cert_data: PEM-encoded certificate bytes
    
    Returns:
        X.509 certificate object
    """
    if isinstance(cert_data, str):
        cert_data = cert_data.encode("utf-8")
    
    return x509.load_pem_x509_certificate(
        cert_data,
        backend=default_backend()
    )


def verify_ca_signature(certificate, ca_certificate) -> bool:
    """
    Verify that a certificate is signed by the CA.
    
    Args:
        certificate: Certificate to verify (X.509 certificate object)
        ca_certificate: CA certificate (X.509 certificate object)
    
    Returns:
        True if certificate is signed by CA, False otherwise
    """
    try:
        # Get the CA's public key
        from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
        from cryptography.hazmat.primitives import hashes
        
        ca_public_key = ca_certificate.public_key()
        
        # Determine the signature algorithm from the certificate
        sig_alg = certificate.signature_algorithm_oid
        
        # Check if it's RSA with SHA-256 (most common)
        if sig_alg == x509.SignatureAlgorithmOID.RSA_WITH_SHA256:
            ca_public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                rsa_padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
        else:
            # For other algorithms, try using the signature algorithm directly
            # This is a fallback for other signature types
            ca_public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                certificate.signature_algorithm
            )
            return True
    except InvalidSignature:
        return False
    except Exception as e:
        # Handle other verification errors
        return False


def check_validity(certificate, current_time: datetime = None) -> bool:
    """
    Check if a certificate is within its validity period.
    
    Args:
        certificate: X.509 certificate object
        current_time: Current time to check against (default: now)
    
    Returns:
        True if certificate is valid (not expired, not before validity period), False otherwise
    """
    if current_time is None:
        current_time = datetime.utcnow()
    
    # Check if current time is before certificate's not_valid_before
    if current_time < certificate.not_valid_before:
        return False
    
    # Check if current time is after certificate's not_valid_after
    if current_time > certificate.not_valid_after:
        return False
    
    return True


def get_common_name(certificate) -> str:
    """
    Extract the Common Name (CN) from a certificate's subject.
    
    Args:
        certificate: X.509 certificate object
    
    Returns:
        Common Name as string, or None if not found
    """
    try:
        subject = certificate.subject
        cn_attributes = subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn_attributes:
            return cn_attributes[0].value
    except Exception:
        pass
    return None


def get_san_dns_names(certificate) -> list[str]:
    """
    Extract DNS names from Subject Alternative Name (SAN) extension.
    
    Args:
        certificate: X.509 certificate object
    
    Returns:
        List of DNS names from SAN extension, or empty list if not found
    """
    try:
        san_ext = certificate.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        san = san_ext.value
        dns_names = [
            name.value 
            for name in san 
            if isinstance(name, x509.DNSName)
        ]
        return dns_names
    except x509.ExtensionNotFound:
        return []
    except Exception:
        return []


def validate_certificate(
    certificate,
    ca_certificate,
    expected_cn: str = None,
    current_time: datetime = None
) -> tuple[bool, str]:
    """
    Comprehensive certificate validation: CA signature, validity, and CN/SAN.
    
    Args:
        certificate: Certificate to validate (X.509 certificate object)
        ca_certificate: CA certificate for signature verification
        expected_cn: Expected Common Name (optional)
        current_time: Current time for validity check (default: now)
    
    Returns:
        Tuple of (is_valid, error_message)
        - is_valid: True if certificate passes all checks
        - error_message: Error description if validation fails, empty string if valid
    """
    # Check 1: Verify CA signature
    if not verify_ca_signature(certificate, ca_certificate):
        return False, "Certificate not signed by CA"
    
    # Check 2: Verify validity period
    if not check_validity(certificate, current_time):
        validity_msg = ""
        if current_time is None:
            current_time = datetime.utcnow()
        if current_time < certificate.not_valid_before:
            validity_msg = f"Certificate not yet valid (valid from {certificate.not_valid_before})"
        elif current_time > certificate.not_valid_after:
            validity_msg = f"Certificate expired (expired on {certificate.not_valid_after})"
        else:
            validity_msg = "Certificate validity check failed"
        return False, validity_msg
    
    # Check 3: Verify CN/SAN if expected_cn is provided
    if expected_cn is not None:
        cn = get_common_name(certificate)
        san_dns_names = get_san_dns_names(certificate)
        
        # Check if expected_cn matches CN or any SAN DNS name
        matches_cn = (cn == expected_cn) if cn else False
        matches_san = expected_cn in san_dns_names
        
        if not (matches_cn or matches_san):
            cn_info = f"CN={cn}" if cn else "CN=None"
            san_info = f"SAN={san_dns_names}" if san_dns_names else "SAN=None"
            return False, f"Certificate CN/SAN mismatch: expected {expected_cn}, got {cn_info}, {san_info}"
    
    return True, ""
