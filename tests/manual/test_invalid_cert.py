"""Test: Invalid certificate rejection (BAD_CERT)."""

import socket
import json
from app.common.protocol import Hello, Error, MessageType
from app.common.utils import b64e
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta


def create_self_signed_cert():
    """Create a self-signed certificate (not signed by CA)."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "fake.client.local"),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).sign(private_key, hashes.SHA256(), default_backend())
    
    return cert.public_bytes(serialization.Encoding.PEM)


def create_expired_cert():
    """Create an expired certificate."""
    from app.crypto.pki import load_ca_certificate
    from scripts.gen_ca import create_root_ca
    
    # Load CA
    ca_private_key, ca_cert = create_root_ca("Test CA", validity_years=1)
    
    # Create cert that expired yesterday
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "expired.client.local"),
    ])
    issuer = ca_cert.subject
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow() - timedelta(days=400)
    ).not_valid_after(
        datetime.utcnow() - timedelta(days=1)  # Expired yesterday
    ).sign(ca_private_key, hashes.SHA256(), default_backend())
    
    return cert.public_bytes(serialization.Encoding.PEM)


def test_invalid_cert(host="localhost", port=3037):
    """Test that invalid certificates are rejected."""
    print("=" * 60)
    print("TEST: Invalid Certificate Rejection (BAD_CERT)")
    print("=" * 60)
    
    # Test 1: Self-signed certificate
    print("\n[Test 1] Sending self-signed certificate...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        
        fake_cert = create_self_signed_cert()
        hello = Hello(cert=b64e(fake_cert))
        
        data = json.dumps(hello.model_dump()).encode("utf-8")
        length = len(data).to_bytes(4, byteorder="big")
        sock.sendall(length + data)
        
        # Receive response
        length_bytes = sock.recv(4)
        length = int.from_bytes(length_bytes, byteorder="big")
        data = sock.recv(length)
        response = json.loads(data.decode("utf-8"))
        
        if response.get("type") == MessageType.ERROR:
            error = Error(**response)
            if error.code == "BAD_CERT":
                print(f"✓ PASSED: Self-signed cert rejected with BAD_CERT")
                print(f"  Error message: {error.message}")
            else:
                print(f"✗ FAILED: Expected BAD_CERT, got {error.code}")
        else:
            print(f"✗ FAILED: Expected ERROR, got {response.get('type')}")
        
        sock.close()
    except Exception as e:
        print(f"✗ FAILED: Exception: {e}")
    
    # Test 2: Expired certificate
    print("\n[Test 2] Sending expired certificate...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        
        expired_cert = create_expired_cert()
        hello = Hello(cert=b64e(expired_cert))
        
        data = json.dumps(hello.model_dump()).encode("utf-8")
        length = len(data).to_bytes(4, byteorder="big")
        sock.sendall(length + data)
        
        # Receive response
        length_bytes = sock.recv(4)
        length = int.from_bytes(length_bytes, byteorder="big")
        data = sock.recv(length)
        response = json.loads(data.decode("utf-8"))
        
        if response.get("type") == MessageType.ERROR:
            error = Error(**response)
            if error.code == "BAD_CERT":
                print(f"✓ PASSED: Expired cert rejected with BAD_CERT")
                print(f"  Error message: {error.message}")
            else:
                print(f"✗ FAILED: Expected BAD_CERT, got {error.code}")
        else:
            print(f"✗ FAILED: Expected ERROR, got {response.get('type')}")
        
        sock.close()
    except Exception as e:
        print(f"✗ FAILED: Exception: {e}")
    
    print("\n" + "=" * 60)


if __name__ == "__main__":
    import sys
    host = sys.argv[1] if len(sys.argv) > 1 else "localhost"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 3037
    test_invalid_cert(host, port)

