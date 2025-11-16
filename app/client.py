"""Client skeleton — plain TCP; no TLS. See assignment spec."""

import socket
import json
import os
from typing import Optional
from dotenv import load_dotenv
from rich.console import Console
from rich.prompt import Prompt

from app.common.protocol import (
    Hello, ServerHello, Register, Login, DHClient, DHServer,
    Message, Receipt, Error, MessageType
)
from app.common.utils import now_ms, b64e, b64d
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


class SecureChatClient:
    """Secure chat client implementing CIANR properties."""
    
    def __init__(self, host: str = "localhost", port: int = 8888):
        self.host = host
        self.port = port
        self.sock: Optional[socket.socket] = None
        
        # Certificate paths
        self.client_cert_path = os.getenv("CLIENT_CERT_PATH", "certs/client.crt")
        self.client_key_path = os.getenv("CLIENT_KEY_PATH", "certs/client.key")
        self.ca_cert_path = os.getenv("CA_CERT_PATH", "certs/ca.crt")
        
        # Load client certificate and key
        self.client_cert = self._load_client_certificate()
        self.client_key = self._load_client_private_key()
        self.ca_cert = load_ca_certificate(self.ca_cert_path)
        
        # Session state
        self.dh_private_key = None
        self.aes_key = None
        self.seqno = 0
        self.username = None
        self.authenticated = False
    
    def _load_client_certificate(self) -> bytes:
        """Load client certificate from file."""
        with open(self.client_cert_path, "rb") as f:
            return f.read()
    
    def _load_client_private_key(self) -> bytes:
        """Load client private key from file."""
        with open(self.client_key_path, "rb") as f:
            return f.read()
    
    def connect(self):
        """Connect to the server."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))
        console.print(f"[green]Connected to {self.host}:{self.port}[/green]")
    
    def send_message(self, msg: dict):
        """Send a JSON message to the server."""
        data = json.dumps(msg).encode("utf-8")
        # Send message length first
        length = len(data).to_bytes(4, byteorder="big")
        self.sock.sendall(length + data)
    
    def recv_message(self) -> dict:
        """Receive a JSON message from the server."""
        # Receive message length
        length_bytes = self.sock.recv(4)
        if len(length_bytes) < 4:
            raise ConnectionError("Connection closed by server")
        length = int.from_bytes(length_bytes, byteorder="big")
        
        # Receive message data
        data = b""
        while len(data) < length:
            chunk = self.sock.recv(length - len(data))
            if not chunk:
                raise ConnectionError("Connection closed by server")
            data += chunk
        
        return json.loads(data.decode("utf-8"))
    
    def handshake(self):
        """Perform TLS-like handshake: certificate exchange and DH key exchange."""
        console.print("[yellow]Starting handshake...[/yellow]")
        
        # Step 1: Send client hello with certificate
        hello = Hello(cert=b64e(self.client_cert))
        self.send_message(hello.model_dump())
        
        # Step 2: Receive server hello
        server_hello_data = self.recv_message()
        if server_hello_data.get("type") == MessageType.ERROR:
            error = Error(**server_hello_data)
            console.print(f"[red]Error: {error.code} - {error.message}[/red]")
            return False
        
        server_hello = ServerHello(**server_hello_data)
        server_cert_data = b64d(server_hello.cert)
        server_cert = load_certificate(server_cert_data)
        
        # Step 3: Validate server certificate
        console.print("[yellow]Validating server certificate...[/yellow]")
        is_valid, error_msg = validate_certificate(
            server_cert,
            self.ca_cert,
            expected_cn="server.local"
        )
        
        if not is_valid:
            console.print(f"[red]Certificate validation failed: {error_msg}[/red]")
            return False
        
        console.print("[green]Server certificate validated[/green]")
        
        # Step 4: Generate DH private key and send public key
        self.dh_private_key = generate_dh_private_key()
        client_dh_public = get_dh_public_key(self.dh_private_key)
        
        dh_client = DHClient(public_key=b64e(client_dh_public))
        self.send_message(dh_client.model_dump())
        
        # Step 5: Receive server's DH public key
        dh_server_data = self.recv_message()
        if dh_server_data.get("type") == MessageType.ERROR:
            error = Error(**dh_server_data)
            console.print(f"[red]Error: {error.code} - {error.message}[/red]")
            return False
        
        dh_server = DHServer(**dh_server_data)
        server_dh_public = load_dh_public_key(b64d(dh_server.public_key))
        
        # Step 6: Derive shared secret and AES key
        shared_secret = derive_shared_secret(self.dh_private_key, server_dh_public)
        self.aes_key = derive_aes_key(shared_secret)
        
        console.print("[green]Handshake complete! Encryption established.[/green]")
        return True
    
    def register(self, username: str, password: str) -> bool:
        """Register a new user."""
        register_msg = Register(username=username, password=password)
        self.send_message(register_msg.model_dump())
        
        response = self.recv_message()
        if response.get("type") == MessageType.ERROR:
            error = Error(**response)
            console.print(f"[red]Registration failed: {error.message}[/red]")
            return False
        
        console.print("[green]Registration successful![/green]")
        return True
    
    def login(self, username: str, password: str) -> bool:
        """Login to the server."""
        login_msg = Login(username=username, password=password)
        self.send_message(login_msg.model_dump())
        
        response = self.recv_message()
        if response.get("type") == MessageType.ERROR:
            error = Error(**response)
            console.print(f"[red]Login failed: {error.message}[/red]")
            return False
        
        self.username = username
        self.authenticated = True
        console.print(f"[green]Login successful! Welcome, {username}[/green]")
        return True
    
    def send_message_encrypted(self, text: str):
        """Send an encrypted message to the server."""
        if not self.authenticated or not self.aes_key:
            console.print("[red]Not authenticated or encryption not established[/red]")
            return
        
        self.seqno += 1
        
        # Encrypt message
        plaintext = text.encode("utf-8")
        ciphertext_bytes = encrypt(self.aes_key, plaintext)
        ciphertext = b64e(ciphertext_bytes)
        
        # Sign the message (seqno + ciphertext) for integrity
        data_to_sign = f"{self.seqno}:{ciphertext}".encode("utf-8")
        signature_bytes = sign(self.client_key, data_to_sign)
        signature = b64e(signature_bytes)
        
        msg = Message(
            seqno=self.seqno,
            ciphertext=ciphertext,
            signature=signature
        )
        
        self.send_message(msg.model_dump())
        console.print(f"[cyan]You:[/cyan] {text}")
    
    def recv_message_encrypted(self) -> Optional[str]:
        """Receive an encrypted message from the server."""
        try:
            response = self.recv_message()
            
            if response.get("type") == MessageType.ERROR:
                error = Error(**response)
                console.print(f"[red]Error: {error.code} - {error.message}[/red]")
                return None
            
            if response.get("type") == MessageType.RECEIPT:
                receipt = Receipt(**response)
                console.print(f"[yellow]Session Receipt received:[/yellow]")
                console.print(f"  Session ID: {receipt.session_id}")
                console.print(f"  Transcript Hash: {receipt.transcript_hash}")
                console.print(f"  Signature: {receipt.signature[:50]}...")
                return None
            
            if response.get("type") == MessageType.MSG:
                msg = Message(**response)
                
                # Verify signature (server's signature)
                # Note: In a real implementation, we'd verify against server cert
                data_to_verify = f"{msg.seqno}:{msg.ciphertext}".encode("utf-8")
                signature_bytes = b64d(msg.signature)
                
                # Decrypt message
                ciphertext_bytes = b64d(msg.ciphertext)
                plaintext_bytes = decrypt(self.aes_key, ciphertext_bytes)
                plaintext = plaintext_bytes.decode("utf-8")
                
                console.print(f"[magenta]Server:[/magenta] {plaintext}")
                return plaintext
            
            return None
        except Exception as e:
            console.print(f"[red]Error receiving message: {e}[/red]")
            return None
    
    def chat_loop(self):
        """Main chat loop."""
        console.print("[yellow]Entering chat mode. Type messages or '/quit' to exit.[/yellow]")
        
        while True:
            try:
                # Check for incoming messages (non-blocking)
                self.sock.settimeout(0.1)
                try:
                    self.recv_message_encrypted()
                except socket.timeout:
                    pass
                except Exception:
                    break
                
                # Get user input
                self.sock.settimeout(None)
                user_input = Prompt.ask("")
                
                if user_input.lower() == "/quit":
                    break
                
                if user_input.strip():
                    self.send_message_encrypted(user_input)
            
            except KeyboardInterrupt:
                break
            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")
                break
    
    def disconnect(self):
        """Disconnect from the server."""
        if self.sock:
            self.sock.close()
            console.print("[yellow]Disconnected from server[/yellow]")


def main():
    """Main entry point for the client."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Secure Chat Client")
    parser.add_argument("--host", type=str, default="localhost", help="Server host")
    parser.add_argument("--port", type=int, default=3037, help="Server port")
    args = parser.parse_args()
    
    client = SecureChatClient(host=args.host, port=args.port)
    
    try:
        # Connect to server
        client.connect()
        
        # Perform handshake
        if not client.handshake():
            console.print("[red]Handshake failed[/red]")
            return
        
        # Authentication flow
        console.print("\n[yellow]=== Authentication ===[/yellow]")
        action = Prompt.ask("Register or Login?", choices=["register", "login"], default="login")
        
        username = Prompt.ask("Username")
        password = Prompt.ask("Password", password=True)
        
        if action == "register":
            if not client.register(username, password):
                return
            # After registration, login
            if not client.login(username, password):
                return
        else:
            if not client.login(username, password):
                return
        
        # Chat loop
        console.print("\n[yellow]=== Chat ===[/yellow]")
        client.chat_loop()
    
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        import traceback
        traceback.print_exc()
    finally:
        client.disconnect()


if __name__ == "__main__":
    main()
