"""Test: Message tampering detection (SIG_FAIL)."""

import socket
import json
import base64
from app.common.protocol import Hello, ServerHello, DHClient, DHServer, Message, Error, MessageType
from app.common.utils import b64e, b64d
from app.crypto.pki import load_ca_certificate, load_certificate, validate_certificate
from app.crypto.dh import generate_dh_private_key, get_dh_public_key, load_dh_public_key, derive_shared_secret, derive_aes_key
from app.crypto.aes import encrypt
from app.crypto.sign import sign


def tamper_ciphertext(ciphertext_b64: str) -> str:
    """Flip a bit in the ciphertext."""
    ciphertext_bytes = b64d(ciphertext_b64)
    # Flip the first bit of the first byte
    tampered = bytearray(ciphertext_bytes)
    tampered[0] ^= 0x01
    return b64e(bytes(tampered))


def test_tamper(host="localhost", port=3037):
    """Test that tampered messages are rejected."""
    print("=" * 60)
    print("TEST: Message Tampering Detection (SIG_FAIL)")
    print("=" * 60)
    
    try:
        # Load client cert and key
        with open("certs/client.crt", "rb") as f:
            client_cert_data = f.read()
        with open("certs/client.key", "rb") as f:
            client_key_data = f.read()
        
        # Connect and perform handshake
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        
        # Send hello
        hello = Hello(cert=b64e(client_cert_data))
        data = json.dumps(hello.model_dump()).encode("utf-8")
        sock.sendall(len(data).to_bytes(4, byteorder="big") + data)
        
        # Receive server hello
        length_bytes = sock.recv(4)
        length = int.from_bytes(length_bytes, byteorder="big")
        data = sock.recv(length)
        server_hello = ServerHello(**json.loads(data.decode("utf-8")))
        
        # Validate server cert
        server_cert = load_certificate(b64d(server_hello.cert))
        ca_cert = load_ca_certificate("certs/ca.crt")
        is_valid, _ = validate_certificate(server_cert, ca_cert, "server.local")
        if not is_valid:
            print("✗ FAILED: Server cert validation failed")
            return
        
        # DH key exchange
        dh_private = generate_dh_private_key()
        client_dh_public = get_dh_public_key(dh_private)
        dh_client = DHClient(public_key=b64e(client_dh_public))
        data = json.dumps(dh_client.model_dump()).encode("utf-8")
        sock.sendall(len(data).to_bytes(4, byteorder="big") + data)
        
        length_bytes = sock.recv(4)
        length = int.from_bytes(length_bytes, byteorder="big")
        data = sock.recv(length)
        dh_server = DHServer(**json.loads(data.decode("utf-8")))
        
        server_dh_public = load_dh_public_key(b64d(dh_server.public_key))
        shared_secret = derive_shared_secret(dh_private, server_dh_public)
        aes_key = derive_aes_key(shared_secret)
        
        # Login (simplified - you may need to adjust based on your server)
        # For this test, we'll just send a tampered message
        
        # Create a valid message
        plaintext = "Hello, this is a test message"
        ciphertext_bytes = encrypt(aes_key, plaintext.encode("utf-8"))
        ciphertext = b64e(ciphertext_bytes)
        
        # Sign the original message
        seqno = 1
        data_to_sign = f"{seqno}:{ciphertext}".encode("utf-8")
        signature_bytes = sign(client_key_data, data_to_sign)
        signature = b64e(signature_bytes)
        
        # Now tamper with the ciphertext
        tampered_ciphertext = tamper_ciphertext(ciphertext)
        
        # Send tampered message with original signature
        msg = Message(
            seqno=seqno,
            ciphertext=tampered_ciphertext,  # Tampered!
            signature=signature  # Original signature
        )
        
        print("\n[Test] Sending tampered message (flipped bit in ciphertext)...")
        data = json.dumps(msg.model_dump()).encode("utf-8")
        sock.sendall(len(data).to_bytes(4, byteorder="big") + data)
        
        # Receive response
        length_bytes = sock.recv(4)
        length = int.from_bytes(length_bytes, byteorder="big")
        data = sock.recv(length)
        response = json.loads(data.decode("utf-8"))
        
        if response.get("type") == MessageType.ERROR:
            error = Error(**response)
            if error.code == "SIG_FAIL":
                print(f"✓ PASSED: Tampered message rejected with SIG_FAIL")
                print(f"  Error message: {error.message}")
            elif error.code == "DECRYPT_FAIL":
                print(f"✓ PASSED: Tampered message rejected (decryption failed)")
                print(f"  Error message: {error.message}")
            else:
                print(f"⚠ PARTIAL: Got error {error.code}, expected SIG_FAIL")
                print(f"  Error message: {error.message}")
        else:
            print(f"✗ FAILED: Expected ERROR, got {response.get('type')}")
            print(f"  Response: {response}")
        
        sock.close()
        
    except Exception as e:
        print(f"✗ FAILED: Exception: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n" + "=" * 60)


if __name__ == "__main__":
    import sys
    host = sys.argv[1] if len(sys.argv) > 1 else "localhost"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 3037
    test_tamper(host, port)

