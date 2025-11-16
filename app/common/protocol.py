"""Pydantic models: hello, server_hello, register, login, dh_client, dh_server, msg, receipt."""

from pydantic import BaseModel
from enum import Enum


class MessageType(str, Enum):
    """Message types in the protocol."""
    HELLO = "hello"
    SERVER_HELLO = "server_hello"
    REGISTER = "register"
    LOGIN = "login"
    DH_CLIENT = "dh_client"
    DH_SERVER = "dh_server"
    MSG = "msg"
    RECEIPT = "receipt"
    ERROR = "error"


class Hello(BaseModel):
    """Client hello message with certificate."""
    type: str = MessageType.HELLO
    cert: str  # Base64-encoded client certificate


class ServerHello(BaseModel):
    """Server hello message with certificate."""
    type: str = MessageType.SERVER_HELLO
    cert: str  # Base64-encoded server certificate


class Register(BaseModel):
    """User registration request."""
    type: str = MessageType.REGISTER
    username: str
    password: str  # Plain password (will be hashed server-side)


class Login(BaseModel):
    """User login request."""
    type: str = MessageType.LOGIN
    username: str
    password: str  # Plain password (will be hashed server-side)


class DHClient(BaseModel):
    """Client's DH public key."""
    type: str = MessageType.DH_CLIENT
    public_key: str  # Base64-encoded DH public key


class DHServer(BaseModel):
    """Server's DH public key."""
    type: str = MessageType.DH_SERVER
    public_key: str  # Base64-encoded DH public key


class Message(BaseModel):
    """Encrypted chat message."""
    type: str = MessageType.MSG
    seqno: int  # Sequence number for replay protection
    ciphertext: str  # Base64-encoded encrypted message
    signature: str  # Base64-encoded signature for integrity


class Receipt(BaseModel):
    """Session receipt for non-repudiation."""
    type: str = MessageType.RECEIPT
    session_id: str  # Session identifier
    transcript_hash: str  # Hash of the session transcript
    signature: str  # Base64-encoded signature of transcript_hash


class Error(BaseModel):
    """Error message."""
    type: str = MessageType.ERROR
    code: str  # Error code (e.g., "BAD_CERT", "SIG_FAIL", "REPLAY", "AUTH_FAIL")
    message: str  # Human-readable error message
