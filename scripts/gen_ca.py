"""Create Root CA (RSA + self-signed X.509) using cryptography."""

import argparse
import os
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


def create_root_ca(ca_name: str, key_size: int = 2048, validity_years: int = 10):
    """
    Create a Root CA with RSA key and self-signed X.509 certificate.
    
    Args:
        ca_name: Name for the Certificate Authority
        key_size: RSA key size in bits (default: 2048)
        validity_years: Certificate validity period in years (default: 10)
    
    Returns:
        Tuple of (private_key, certificate)
    """
    # Generate RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    
    # Create subject name (CN = ca_name)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Karachi"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Karachi"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NU"),
        x509.NameAttribute(NameOID.COMMON_NAME, ca_name),
    ])
    
    # Certificate validity period
    now = datetime.utcnow()
    validity_start = now
    validity_end = now + timedelta(days=365 * validity_years)
    
    # Build the certificate
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)  # Self-signed
    builder = builder.public_key(private_key.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(validity_start)
    builder = builder.not_valid_after(validity_end)
    
    # Add extensions for CA certificate
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    )
    
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,  # Can sign certificates
            crl_sign=True,       # Can sign CRLs
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
        critical=False,
    )
    
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(private_key.public_key()),
        critical=False,
    )
    
    # Sign the certificate with the private key
    certificate = builder.sign(
        private_key=private_key,
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )
    
    return private_key, certificate


def save_ca_files(private_key, certificate, output_dir: str = "certs"):
    """
    Save CA private key and certificate to files.
    
    Args:
        private_key: RSA private key
        certificate: X.509 certificate
        output_dir: Directory to save files (default: "certs")
    """
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Save private key (PEM format, encrypted with no password for this assignment)
    key_path = os.path.join(output_dir, "ca.key")
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    os.chmod(key_path, 0o600)  # Restrict permissions (read/write for owner only)
    print(f"✓ CA private key saved to: {key_path}")
    
    # Save certificate (PEM format)
    cert_path = os.path.join(output_dir, "ca.crt")
    with open(cert_path, "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))
    print(f"✓ CA certificate saved to: {cert_path}")
    
    # Print certificate details
    print(f"\nCertificate Details:")
    print(f"  Subject: {certificate.subject.rfc4514_string()}")
    print(f"  Issuer: {certificate.issuer.rfc4514_string()}")
    print(f"  Serial: {certificate.serial_number}")
    print(f"  Valid from: {certificate.not_valid_before}")
    print(f"  Valid until: {certificate.not_valid_after}")


def main():
    """Main entry point for CA generation."""
    parser = argparse.ArgumentParser(
        description="Generate a Root Certificate Authority (CA)"
    )
    parser.add_argument(
        "--name",
        type=str,
        default="FAST-NU Root CA",
        help="Name for the Certificate Authority (default: 'FAST-NU Root CA')"
    )
    parser.add_argument(
        "--key-size",
        type=int,
        default=2048,
        choices=[2048, 3072, 4096],
        help="RSA key size in bits (default: 2048)"
    )
    parser.add_argument(
        "--validity-years",
        type=int,
        default=10,
        help="Certificate validity period in years (default: 10)"
    )
    parser.add_argument(
        "--out-dir",
        type=str,
        default="certs",
        help="Output directory for CA files (default: 'certs')"
    )
    
    args = parser.parse_args()
    
    print(f"Generating Root CA: {args.name}")
    print(f"Key size: {args.key_size} bits")
    print(f"Validity: {args.validity_years} years")
    print()
    
    try:
        private_key, certificate = create_root_ca(
            ca_name=args.name,
            key_size=args.key_size,
            validity_years=args.validity_years
        )
        
        save_ca_files(private_key, certificate, output_dir=args.out_dir)
        
        print(f"\n✓ Root CA generated successfully!")
        
    except Exception as e:
        print(f"\n✗ Error generating CA: {e}")
        raise


if __name__ == "__main__":
    main()
