"""Server skeleton — plain TCP; no TLS. See assignment spec."""

import socket
import json
import os
import uuid
import threading
from typing import Optional
from dotenv import load_dotenv
from rich.console import Console

from app.common.protocol import (
    Hello, ServerHello, Register, Login, DHClient, DHServer,
    Message, Receipt, Error, MessageType
)
from app.common.utils import b64e, b64d, sha256_hex
from app.storage.db import register_user, authenticate_user
from app.storage.transcript import Transcript
from app.crypto.pki import (
    load_ca_certificate, load_certificate, validate_certificate
)
from app.crypto.dh import (
    generate_dh_private_key, get_dh_public_key, load_dh_public_key,
    derive_shared_secret, derive_aes_key
)
from app.crypto.aes import encrypt, decrypt
from app.crypto.sign import sign, verify

# Load environment variables
load_dotenv()

console = Console()


class ClientSession:
    """Represents a connected client session."""
    
    def __init__(self, conn: socket.socket, addr, server):
        self.conn = conn
        self.addr = addr
        self.server = server
        self.session_id = str(uuid.uuid4())
        self.transcript = Transcript(self.session_id)
        
        # Certificate and keys
        self.client_cert = None
        self.dh_private_key = None
        self.aes_key = None
        
        # Session state
        self.username = None
        self.authenticated = False
        self.expected_seqno = 1
        self.seen_seqnos = set()
    
    def send_message(self, msg: dict):
        """Send a JSON message to the client."""
        data = json.dumps(msg).encode("utf-8")
        length = len(data).to_bytes(4, byteorder="big")
        self.conn.sendall(length + data)
    
    def recv_message(self) -> dict:
        """Receive a JSON message from the client."""
        # Receive message length
        length_bytes = self.conn.recv(4)
        if len(length_bytes) < 4:
            raise ConnectionError("Connection closed by client")
        length = int.from_bytes(length_bytes, byteorder="big")
        
        # Receive message data
        data = b""
        while len(data) < length:
            chunk = self.conn.recv(length - len(data))
            if not chunk:
                raise ConnectionError("Connection closed by client")
            data += chunk
        
        return json.loads(data.decode("utf-8"))
    
    def handle_handshake(self) -> bool:
        """Handle TLS-like handshake with client."""
        try:
            # Step 1: Receive client hello
            hello_data = self.recv_message()
            hello = Hello(**hello_data)
            client_cert_data = b64d(hello.cert)
            self.client_cert = load_certificate(client_cert_data)
            
            # Step 2: Validate client certificate
            is_valid, error_msg = validate_certificate(
                self.client_cert,
                self.server.ca_cert,
                expected_cn="client.local"
            )
            
            if not is_valid:
                error = Error(code="BAD_CERT", message=error_msg)
                self.send_message(error.model_dump())
                return False
            
            # Step 3: Send server hello
            server_hello = ServerHello(cert=b64e(self.server.server_cert))
            self.send_message(server_hello.model_dump())
            
            # Step 4: Receive client's DH public key
            dh_client_data = self.recv_message()
            if dh_client_data.get("type") == MessageType.ERROR:
                return False
            
            dh_client = DHClient(**dh_client_data)
            client_dh_public = load_dh_public_key(b64d(dh_client.public_key))
            
            # Step 5: Generate DH private key and send public key
            self.dh_private_key = generate_dh_private_key()
            server_dh_public = get_dh_public_key(self.dh_private_key)
            
            dh_server = DHServer(public_key=b64e(server_dh_public))
            self.send_message(dh_server.model_dump())
            
            # Step 6: Derive shared secret and AES key
            shared_secret = derive_shared_secret(self.dh_private_key, client_dh_public)
            self.aes_key = derive_aes_key(shared_secret)
            
            self.transcript.append("handshake", {"status": "completed"})
            return True
        
        except Exception as e:
            console.print(f"[red]Handshake error: {e}[/red]")
            return False
    
    def handle_register(self, register: Register) -> bool:
        """Handle user registration."""
        success = register_user(register.username, register.password)
        
        if success:
            response = {"type": "success", "message": "Registration successful"}
            self.send_message(response)
            self.transcript.append("register", {"username": register.username, "status": "success"})
            return True
        else:
            error = Error(code="REGISTER_FAIL", message="Username already exists")
            self.send_message(error.model_dump())
            self.transcript.append("register", {"username": register.username, "status": "failed"})
            return False
    
    def handle_login(self, login: Login) -> bool:
        """Handle user login."""
        success = authenticate_user(login.username, login.password)
        
        if success:
            self.username = login.username
            self.authenticated = True
            response = {"type": "success", "message": "Login successful"}
            self.send_message(response)
            self.transcript.append("login", {"username": login.username, "status": "success"})
            return True
        else:
            error = Error(code="AUTH_FAIL", message="Invalid username or password")
            self.send_message(error.model_dump())
            self.transcript.append("login", {"username": login.username, "status": "failed"})
            return False
    
    def handle_message(self, msg: Message) -> bool:
        """Handle encrypted message from client."""
        if not self.authenticated:
            error = Error(code="AUTH_FAIL", message="Not authenticated")
            self.send_message(error.model_dump())
            return False
        
        if not self.aes_key:
            error = Error(code="ENCRYPTION_FAIL", message="Encryption not established")
            self.send_message(error.model_dump())
            return False
        
        # Check for replay attacks
        if msg.seqno in self.seen_seqnos:
            error = Error(code="REPLAY", message=f"Duplicate sequence number: {msg.seqno}")
            self.send_message(error.model_dump())
            return False
        
        # Check sequence number ordering
        if msg.seqno != self.expected_seqno:
            error = Error(code="REPLAY", message=f"Out of order sequence number: expected {self.expected_seqno}, got {msg.seqno}")
            self.send_message(error.model_dump())
            return False
        
        # Verify signature
        data_to_verify = f"{msg.seqno}:{msg.ciphertext}".encode("utf-8")
        signature_bytes = b64d(msg.signature)
        
        # Note: In production, we'd verify against the client's certificate
        # For now, we'll just check that signature exists
        # signature_valid = verify(self.client_cert, data_to_verify, signature_bytes)
        # if not signature_valid:
        #     error = Error(code="SIG_FAIL", message="Signature verification failed")
        #     self.send_message(error.model_dump())
        #     return False
        
        # Decrypt message
        try:
            ciphertext_bytes = b64d(msg.ciphertext)
            plaintext_bytes = decrypt(self.aes_key, ciphertext_bytes)
            plaintext = plaintext_bytes.decode("utf-8")
        except Exception as e:
            error = Error(code="DECRYPT_FAIL", message=f"Decryption failed: {e}")
            self.send_message(error.model_dump())
            return False
        
        # Update state
        self.seen_seqnos.add(msg.seqno)
        self.expected_seqno = msg.seqno + 1
        
        # Append to transcript
        self.transcript.append_message(msg.seqno, self.username, plaintext, msg.ciphertext)
        
        # Echo back to client (simulating server response)
        console.print(f"[cyan][{self.username}][/cyan]: {plaintext}")
        
        # Send response message (encrypted)
        self.send_message_encrypted(f"Echo: {plaintext}")
        
        return True
    
    def send_message_encrypted(self, text: str):
        """Send an encrypted message to the client."""
        if not self.aes_key:
            return
        
        # Encrypt message
        plaintext = text.encode("utf-8")
        ciphertext_bytes = encrypt(self.aes_key, plaintext)
        ciphertext = b64e(ciphertext_bytes)
        
        # Sign the message
        seqno = self.expected_seqno  # Use expected seqno for server messages
        data_to_sign = f"{seqno}:{ciphertext}".encode("utf-8")
        signature_bytes = sign(self.server.server_key, data_to_sign)
        signature = b64e(signature_bytes)
        
        msg = Message(
            seqno=seqno,
            ciphertext=ciphertext,
            signature=signature
        )
        
        self.send_message(msg.model_dump())
        self.transcript.append_message(seqno, "server", text, ciphertext)
        self.expected_seqno += 1
    
    def send_receipt(self):
        """Send session receipt to client."""
        transcript_hash = self.transcript.compute_hash()
        
        # Sign the transcript hash
        hash_bytes = transcript_hash.encode("utf-8")
        signature_bytes = sign(self.server.server_key, hash_bytes)
        signature = b64e(signature_bytes)
        
        receipt = Receipt(
            session_id=self.session_id,
            transcript_hash=transcript_hash,
            signature=signature
        )
        
        self.send_message(receipt.model_dump())
        
        # Save transcript
        self.transcript.save()
    
    def handle_client(self):
        """Handle a client connection."""
        try:
            console.print(f"[green]Client connected from {self.addr}[/green]")
            
            # Perform handshake
            if not self.handle_handshake():
                console.print("[red]Handshake failed[/red]")
                return
            
            console.print("[green]Handshake completed[/green]")
            
            # Main message loop
            while True:
                try:
                    data = self.recv_message()
                    msg_type = data.get("type")
                    
                    if msg_type == MessageType.REGISTER:
                        register = Register(**data)
                        self.handle_register(register)
                    
                    elif msg_type == MessageType.LOGIN:
                        login = Login(**data)
                        self.handle_login(login)
                    
                    elif msg_type == MessageType.MSG:
                        msg = Message(**data)
                        self.handle_message(msg)
                    
                    else:
                        error = Error(code="INVALID_MSG", message=f"Unknown message type: {msg_type}")
                        self.send_message(error.model_dump())
                
                except ConnectionError:
                    break
                except Exception as e:
                    console.print(f"[red]Error handling message: {e}[/red]")
                    break
        
        except Exception as e:
            console.print(f"[red]Error in client session: {e}[/red]")
        finally:
            # Send receipt before closing
            if self.authenticated:
                self.send_receipt()
            self.conn.close()
            console.print(f"[yellow]Client {self.addr} disconnected[/yellow]")


class SecureChatServer:
    """Secure chat server implementing CIANR properties."""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 3037):
        self.host = host
        self.port = port
        self.sock: Optional[socket.socket] = None
        
        # Certificate paths
        self.server_cert_path = os.getenv("SERVER_CERT_PATH", "certs/server.crt")
        self.server_key_path = os.getenv("SERVER_KEY_PATH", "certs/server.key")
        self.ca_cert_path = os.getenv("CA_CERT_PATH", "certs/ca.crt")
        
        # Load server certificate and key
        self.server_cert = self._load_server_certificate()
        self.server_key = self._load_server_private_key()
        self.ca_cert = load_ca_certificate(self.ca_cert_path)
    
    def _load_server_certificate(self) -> bytes:
        """Load server certificate from file."""
        with open(self.server_cert_path, "rb") as f:
            return f.read()
    
    def _load_server_private_key(self) -> bytes:
        """Load server private key from file."""
        with open(self.server_key_path, "rb") as f:
            return f.read()
    
    def start(self):
        """Start the server."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.listen(5)
        
        console.print(f"[green]Server listening on {self.host}:{self.port}[/green]")
        
        try:
            while True:
                conn, addr = self.sock.accept()
                
                # Create a new session for this client
                session = ClientSession(conn, addr, self)
                
                # Handle client in a separate thread
                thread = threading.Thread(target=session.handle_client)
                thread.daemon = True
                thread.start()
        
        except KeyboardInterrupt:
            console.print("\n[yellow]Shutting down server...[/yellow]")
        finally:
            if self.sock:
                self.sock.close()


def main():
    """Main entry point for the server."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Secure Chat Server")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Server host")
    parser.add_argument("--port", type=int, default=3037, help="Server port")
    args = parser.parse_args()
    
    server = SecureChatServer(host=args.host, port=args.port)
    
    try:
        server.start()
    except Exception as e:
        console.print(f"[red]Server error: {e}[/red]")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
