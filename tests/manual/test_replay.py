"""Test: Replay attack detection (REPLAY)."""

import socket
import json
from app.common.protocol import Hello, ServerHello, DHClient, DHServer, Message, Error, MessageType
from app.common.utils import b64e, b64d
from app.crypto.pki import load_ca_certificate, load_certificate, validate_certificate
from app.crypto.dh import generate_dh_private_key, get_dh_public_key, load_dh_public_key, derive_shared_secret, derive_aes_key
from app.crypto.aes import encrypt
from app.crypto.sign import sign


def test_replay(host="localhost", port=3037):
    """Test that replayed messages are rejected."""
    print("=" * 60)
    print("TEST: Replay Attack Detection (REPLAY)")
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
        
        # Create and send first message
        plaintext1 = "First message"
        ciphertext1_bytes = encrypt(aes_key, plaintext1.encode("utf-8"))
        ciphertext1 = b64e(ciphertext1_bytes)
        
        seqno1 = 1
        data_to_sign1 = f"{seqno1}:{ciphertext1}".encode("utf-8")
        signature1_bytes = sign(client_key_data, data_to_sign1)
        signature1 = b64e(signature1_bytes)
        
        msg1 = Message(seqno=seqno1, ciphertext=ciphertext1, signature=signature1)
        print("\n[Step 1] Sending first message (seqno=1)...")
        data = json.dumps(msg1.model_dump()).encode("utf-8")
        sock.sendall(len(data).to_bytes(4, byteorder="big") + data)
        
        # Receive response (ignore for this test)
        length_bytes = sock.recv(4)
        length = int.from_bytes(length_bytes, byteorder="big")
        sock.recv(length)
        
        # Send second message
        plaintext2 = "Second message"
        ciphertext2_bytes = encrypt(aes_key, plaintext2.encode("utf-8"))
        ciphertext2 = b64e(ciphertext2_bytes)
        
        seqno2 = 2
        data_to_sign2 = f"{seqno2}:{ciphertext2}".encode("utf-8")
        signature2_bytes = sign(client_key_data, data_to_sign2)
        signature2 = b64e(signature2_bytes)
        
        msg2 = Message(seqno=seqno2, ciphertext=ciphertext2, signature=signature2)
        print("[Step 2] Sending second message (seqno=2)...")
        data = json.dumps(msg2.model_dump()).encode("utf-8")
        sock.sendall(len(data).to_bytes(4, byteorder="big") + data)
        
        # Receive response
        length_bytes = sock.recv(4)
        length = int.from_bytes(length_bytes, byteorder="big")
        sock.recv(length)
        
        # Now replay the first message
        print("[Step 3] Replaying first message (seqno=1 again)...")
        data = json.dumps(msg1.model_dump()).encode("utf-8")
        sock.sendall(len(data).to_bytes(4, byteorder="big") + data)
        
        # Receive response
        length_bytes = sock.recv(4)
        length = int.from_bytes(length_bytes, byteorder="big")
        data = sock.recv(length)
        response = json.loads(data.decode("utf-8"))
        
        if response.get("type") == MessageType.ERROR:
            error = Error(**response)
            if error.code == "REPLAY":
                print(f"✓ PASSED: Replayed message rejected with REPLAY")
                print(f"  Error message: {error.message}")
            else:
                print(f"✗ FAILED: Expected REPLAY, got {error.code}")
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
    test_replay(host, port)

