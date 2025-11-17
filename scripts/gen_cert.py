"""Issue server/client cert signed by Root CA (SAN=DNSName(CN))."""

import argparse
import os
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


def load_ca(ca_cert_path: str = "certs/ca.crt", ca_key_path: str = "certs/ca.key"):
    """
    Load the CA certificate and private key from files.
    
    Args:
        ca_cert_path: Path to CA certificate file
        ca_key_path: Path to CA private key file
    
    Returns:
        Tuple of (ca_private_key, ca_certificate)
    """
    # Load CA private key
    with open(ca_key_path, "rb") as f:
        ca_private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    
    # Load CA certificate
    with open(ca_cert_path, "rb") as f:
        ca_certificate = x509.load_pem_x509_certificate(
            f.read(),
            backend=default_backend()
        )
    
    return ca_private_key, ca_certificate


def create_certificate(
    cn: str,
    ca_private_key,
    ca_certificate,
    key_size: int = 2048,
    validity_years: int = 1
):
    """
    Create a certificate signed by the Root CA.
    
    Args:
        cn: Common Name (also used in SAN as DNSName)
        ca_private_key: CA's private key for signing
        ca_certificate: CA's certificate
        key_size: RSA key size in bits (default: 2048)
        validity_years: Certificate validity period in years (default: 1)
    
    Returns:
        Tuple of (private_key, certificate)
    """
    # Generate RSA private key for the certificate
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    
    # Create subject name (CN = cn parameter)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Karachi"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Karachi"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NU"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])
    
    # Issuer is the CA's subject
    issuer = ca_certificate.subject
    
    # Certificate validity period
    now = datetime.utcnow()
    validity_start = now
    validity_end = now + timedelta(days=365 * validity_years)
    
    # Build the certificate
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.public_key(private_key.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(validity_start)
    builder = builder.not_valid_after(validity_end)
    
    # Add extensions for server/client certificate (not a CA)
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )
    
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,  # Can encrypt data
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,    # Cannot sign certificates
            crl_sign=False,         # Cannot sign CRLs
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    
    # Add Subject Alternative Name (SAN) with DNSName matching CN
    builder = builder.add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(cn),
        ]),
        critical=False,
    )
    
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
        critical=False,
    )
    
    # Authority Key Identifier should match CA's Subject Key Identifier
    ca_ski = None
    try:
        ca_ski_ext = ca_certificate.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_KEY_IDENTIFIER
        )
        ca_ski = ca_ski_ext.value
    except x509.ExtensionNotFound:
        # Fallback: compute from CA's public key
        ca_ski = x509.SubjectKeyIdentifier.from_public_key(ca_certificate.public_key())
    
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski),
        critical=False,
    )
    
    # Sign the certificate with the CA's private key
    certificate = builder.sign(
        private_key=ca_private_key,
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )
    
    return private_key, certificate


def save_certificate_files(
    private_key,
    certificate,
    output_prefix: str,
    output_dir: str = "certs"
):
    """
    Save certificate private key and certificate to files.
    
    Args:
        private_key: RSA private key
        certificate: X.509 certificate
        output_prefix: Prefix for output files (e.g., "server" -> server.crt, server.key)
        output_dir: Directory to save files (default: "certs")
    """
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Determine full paths
    # If output_prefix already includes directory, use it as-is, otherwise join with output_dir
    if os.path.dirname(output_prefix):
        key_path = f"{output_prefix}.key"
        cert_path = f"{output_prefix}.crt"
    else:
        key_path = os.path.join(output_dir, f"{output_prefix}.key")
        cert_path = os.path.join(output_dir, f"{output_prefix}.crt")
    
    # Save private key (PEM format, unencrypted for this assignment)
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Set restrictive permissions on Windows (if supported)
    try:
        os.chmod(key_path, 0o600)  # Read/write for owner only
    except (OSError, AttributeError):
        # Windows might not support chmod the same way
        pass
    
    print(f"[OK] Private key saved to: {key_path}")
    
    # Save certificate (PEM format)
    with open(cert_path, "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))
    
    print(f"[OK] Certificate saved to: {cert_path}")
    
    # Print certificate details
    print(f"\nCertificate Details:")
    print(f"  Subject: {certificate.subject.rfc4514_string()}")
    print(f"  Issuer: {certificate.issuer.rfc4514_string()}")
    print(f"  Serial: {certificate.serial_number}")
    print(f"  Valid from: {certificate.not_valid_before}")
    print(f"  Valid until: {certificate.not_valid_after}")
    
    # Print SAN if present
    try:
        san_ext = certificate.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        san = san_ext.value
        dns_names = [name.value for name in san if isinstance(name, x509.DNSName)]
        if dns_names:
            print(f"  SAN DNS Names: {', '.join(dns_names)}")
    except x509.ExtensionNotFound:
        pass


def main():
    """Main entry point for certificate generation."""
    parser = argparse.ArgumentParser(
        description="Generate a server/client certificate signed by Root CA"
    )
    parser.add_argument(
        "--cn",
        type=str,
        required=True,
        help="Common Name (CN) for the certificate (also used in SAN as DNSName)"
    )
    parser.add_argument(
        "--out",
        type=str,
        required=True,
        help="Output file prefix (e.g., 'server' creates server.crt and server.key)"
    )
    parser.add_argument(
        "--ca-cert",
        type=str,
        default="certs/ca.crt",
        help="Path to CA certificate file (default: 'certs/ca.crt')"
    )
    parser.add_argument(
        "--ca-key",
        type=str,
        default="certs/ca.key",
        help="Path to CA private key file (default: 'certs/ca.key')"
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
        default=1,
        help="Certificate validity period in years (default: 1)"
    )
    parser.add_argument(
        "--out-dir",
        type=str,
        default="certs",
        help="Output directory for certificate files (default: 'certs')"
    )
    
    args = parser.parse_args()
    
    print(f"Generating certificate for CN: {args.cn}")
    print(f"Key size: {args.key_size} bits")
    print(f"Validity: {args.validity_years} years")
    print(f"Output prefix: {args.out}")
    print()
    
    try:
        # Load CA certificate and key
        print(f"Loading CA from {args.ca_cert} and {args.ca_key}...")
        ca_private_key, ca_certificate = load_ca(args.ca_cert, args.ca_key)
        print("[OK] CA loaded successfully")
        print()
        
        # Create certificate signed by CA
        private_key, certificate = create_certificate(
            cn=args.cn,
            ca_private_key=ca_private_key,
            ca_certificate=ca_certificate,
            key_size=args.key_size,
            validity_years=args.validity_years
        )
        
        # Save certificate and key
        save_certificate_files(
            private_key,
            certificate,
            output_prefix=args.out,
            output_dir=args.out_dir
        )
        
        print(f"\n[OK] Certificate generated successfully!")
        
    except FileNotFoundError as e:
        print(f"\n[ERROR] Error: CA files not found. Please generate the CA first:")
        print(f"  python scripts/gen_ca.py --name 'FAST-NU Root CA'")
        raise
    except Exception as e:
        print(f"\n[ERROR] Error generating certificate: {e}")
        raise


if __name__ == "__main__":
    main()
