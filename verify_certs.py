"""Quick script to verify certificates are valid."""

from app.crypto.pki import load_ca_certificate, load_certificate, validate_certificate
from cryptography.x509.oid import NameOID

print("Verifying certificates...\n")

# Load CA
try:
    ca = load_ca_certificate("certs/ca.crt")
    print(f"[OK] CA Certificate loaded")
    print(f"  Subject: {ca.subject.rfc4514_string()}")
    print(f"  Valid until: {ca.not_valid_after_utc}")
except Exception as e:
    print(f"[ERROR] CA Certificate error: {e}")
    exit(1)

# Verify Server Certificate
try:
    with open("certs/server.crt", "rb") as f:
        server_cert = load_certificate(f.read())
    
    cn_attrs = server_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    cn = cn_attrs[0].value if cn_attrs else "N/A"
    
    print(f"\n[OK] Server Certificate loaded")
    print(f"  CN: {cn}")
    print(f"  Valid until: {server_cert.not_valid_after_utc}")
    
    valid, msg = validate_certificate(server_cert, ca, "server.local")
    if valid:
        print(f"  [OK] Validation: PASSED")
    else:
        print(f"  [ERROR] Validation: FAILED - {msg}")
except Exception as e:
    print(f"\n[ERROR] Server Certificate error: {e}")

# Verify Client Certificate
try:
    with open("certs/client.crt", "rb") as f:
        client_cert = load_certificate(f.read())
    
    cn_attrs = client_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    cn = cn_attrs[0].value if cn_attrs else "N/A"
    
    print(f"\n[OK] Client Certificate loaded")
    print(f"  CN: {cn}")
    print(f"  Valid until: {client_cert.not_valid_after_utc}")
    
    valid, msg = validate_certificate(client_cert, ca, "client.local")
    if valid:
        print(f"  [OK] Validation: PASSED")
    else:
        print(f"  [ERROR] Validation: FAILED - {msg}")
except Exception as e:
    print(f"\n[ERROR] Client Certificate error: {e}")

print("\n[OK] Certificate verification complete!")

