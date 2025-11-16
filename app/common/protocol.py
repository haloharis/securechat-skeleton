"""Pydantic models: hello, server_hello, register, login, dh_client, dh_server, msg, receipt."""

from pydantic import BaseModel, Field
from typing import Optional
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
    type: str = Field(default=MessageType.HELLO, alias="type")
    cert: str  # Base64-encoded client certificate


class ServerHello(BaseModel):
    """Server hello message with certificate."""
    type: str = Field(default=MessageType.SERVER_HELLO, alias="type")
    cert: str  # Base64-encoded server certificate


class Register(BaseModel):
    """User registration request."""
    type: str = Field(default=MessageType.REGISTER, alias="type")
    username: str
    password: str  # Plain password (will be hashed server-side)


class Login(BaseModel):
    """User login request."""
    type: str = Field(default=MessageType.LOGIN, alias="type")
    username: str
    password: str  # Plain password (will be hashed server-side)


class DHClient(BaseModel):
    """Client's DH public key."""
    type: str = Field(default=MessageType.DH_CLIENT, alias="type")
    public_key: str  # Base64-encoded DH public key


class DHServer(BaseModel):
    """Server's DH public key."""
    type: str = Field(default=MessageType.DH_SERVER, alias="type")
    public_key: str  # Base64-encoded DH public key


class Message(BaseModel):
    """Encrypted chat message."""
    type: str = Field(default=MessageType.MSG, alias="type")
    seqno: int  # Sequence number for replay protection
    ciphertext: str  # Base64-encoded encrypted message
    signature: str  # Base64-encoded signature for integrity


class Receipt(BaseModel):
    """Session receipt for non-repudiation."""
    type: str = Field(default=MessageType.RECEIPT, alias="type")
    session_id: str  # Session identifier
    transcript_hash: str  # Hash of the session transcript
    signature: str  # Base64-encoded signature of transcript_hash


class Error(BaseModel):
    """Error message."""
    type: str = Field(default=MessageType.ERROR, alias="type")
    code: str  # Error code (e.g., "BAD_CERT", "SIG_FAIL", "REPLAY", "AUTH_FAIL")
    message: str  # Human-readable error message
