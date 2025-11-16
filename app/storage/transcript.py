"""Append-only transcript + TranscriptHash helpers."""

import os
import json
from typing import List
from datetime import datetime
from app.common.utils import sha256_hex, now_ms


class Transcript:
    """Append-only transcript for session logging."""
    
    def __init__(self, session_id: str, transcript_dir: str = "transcripts"):
        """
        Initialize a transcript for a session.
        
        Args:
            session_id: Unique session identifier
            transcript_dir: Directory to store transcript files
        """
        self.session_id = session_id
        self.transcript_dir = transcript_dir
        self.entries: List[dict] = []
        
        # Create transcript directory if it doesn't exist
        os.makedirs(transcript_dir, exist_ok=True)
    
    def append(self, entry_type: str, data: dict):
        """
        Append an entry to the transcript.
        
        Args:
            entry_type: Type of entry (e.g., "msg", "login", "register")
            data: Entry data
        """
        entry = {
            "timestamp": now_ms(),
            "type": entry_type,
            "data": data
        }
        self.entries.append(entry)
    
    def append_message(self, seqno: int, sender: str, plaintext: str, ciphertext: str):
        """
        Append a message to the transcript.
        
        Args:
            seqno: Sequence number
            sender: Username of the sender
            plaintext: Decrypted message text
            ciphertext: Encrypted message (base64)
        """
        self.append("msg", {
            "seqno": seqno,
            "sender": sender,
            "plaintext": plaintext,
            "ciphertext": ciphertext
        })
    
    def compute_hash(self) -> str:
        """
        Compute the hash of the entire transcript.
        
        Returns:
            SHA-256 hash of the transcript as hexadecimal string
        """
        # Serialize transcript to JSON (sorted keys for consistency)
        transcript_json = json.dumps(self.entries, sort_keys=True, separators=(',', ':'))
        transcript_bytes = transcript_json.encode("utf-8")
        return sha256_hex(transcript_bytes)
    
    def save(self):
        """Save the transcript to a file."""
        filename = os.path.join(self.transcript_dir, f"{self.session_id}.json")
        with open(filename, "w") as f:
            json.dump({
                "session_id": self.session_id,
                "entries": self.entries,
                "hash": self.compute_hash()
            }, f, indent=2)
    
    def get_transcript_summary(self) -> dict:
        """
        Get a summary of the transcript.
        
        Returns:
            Dictionary with session_id, entry_count, and hash
        """
        return {
            "session_id": self.session_id,
            "entry_count": len(self.entries),
            "hash": self.compute_hash()
        }
