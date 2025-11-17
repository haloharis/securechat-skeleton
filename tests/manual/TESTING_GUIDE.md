# Security Testing Guide

This guide demonstrates how to test the security properties of the Secure Chat system.

## Prerequisites

1. **Start the server** (in one terminal):
   ```bash
   python -m app.server
   ```

2. **Ensure certificates are generated**:
   ```bash
   python scripts/gen_ca.py --name "FAST-NU Root CA"
   python scripts/gen_cert.py --cn server.local --out certs/server
   python scripts/gen_cert.py --cn client.local --out certs/client
   ```

## Test 1: Invalid Certificate Rejection (BAD_CERT)

**Objective**: Verify that invalid, self-signed, or expired certificates are rejected.

**Run test**:
```bash
python tests/manual/test_invalid_cert.py
```

**Expected results**:
- Self-signed certificates → `BAD_CERT` error
- Expired certificates → `BAD_CERT` error
- Invalid issuer → `BAD_CERT` error

**What it tests**:
- Certificate validation against CA
- Expiry date checking
- Signature verification

## Test 2: Message Tampering Detection (SIG_FAIL)

**Objective**: Verify that tampered messages are detected and rejected.

**Run test**:
```bash
python tests/manual/test_tamper.py
```

**Expected results**:
- Tampered ciphertext (bit flipped) → `SIG_FAIL` or `DECRYPT_FAIL` error
- Signature verification fails when message is modified

**What it tests**:
- Message integrity protection
- Signature verification
- Tampering detection

## Test 3: Replay Attack Detection (REPLAY)

**Objective**: Verify that replayed messages are rejected.

**Run test**:
```bash
python tests/manual/test_replay.py
```

**Expected results**:
- Replayed sequence number → `REPLAY` error
- Out-of-order sequence numbers → `REPLAY` error

**What it tests**:
- Sequence number tracking
- Replay attack prevention
- Message ordering enforcement

## Test 4: Non-Repudiation Verification

**Objective**: Demonstrate offline verification of session transcripts and receipts.

### Step 1: Generate a Transcript

1. Start the server:
   ```bash
   python -m app.server
   ```

2. Connect with client (in another terminal):
   ```bash
   python -m app.client
   ```

3. Login and send several messages

4. Disconnect (transcript will be saved to `transcripts/<session_id>.json`)

### Step 2: Verify Transcript Offline

```bash
python tests/manual/test_nonrepudiation.py transcripts/<session_id>.json
```

**What it verifies**:
1. **Individual messages**: Each message's integrity
2. **Transcript hash**: SHA-256 hash of entire transcript
3. **Receipt signature**: RSA signature over transcript hash
4. **Tampering detection**: Any modification breaks verification

**Expected output**:
- ✓ Transcript hash matches
- ✓ Receipt signature valid
- ✓ Tampering detected (when transcript is modified)

## Running All Tests

To run all automated tests at once:

```bash
python tests/manual/run_all_tests.py
```

**Note**: Make sure the server is running before executing tests.

## Manual Testing Checklist

### Certificate Validation
- [ ] Self-signed certificate rejected
- [ ] Expired certificate rejected
- [ ] Certificate with wrong CN rejected
- [ ] Valid certificate accepted

### Message Integrity
- [ ] Tampered ciphertext rejected
- [ ] Tampered signature rejected
- [ ] Valid messages accepted

### Replay Protection
- [ ] Duplicate sequence number rejected
- [ ] Out-of-order sequence number rejected
- [ ] Valid sequence numbers accepted

### Non-Repudiation
- [ ] Transcript file generated
- [ ] Receipt generated with signature
- [ ] Transcript hash verifiable
- [ ] Receipt signature verifiable
- [ ] Tampering detected

## Wireshark Capture

To capture network traffic for evidence:

1. **Start Wireshark** and capture on `localhost` or your network interface

2. **Filter**: `tcp.port == 3037`

3. **Run a client session**:
   ```bash
   python -m app.client
   ```

4. **Verify**:
   - All payloads are encrypted (ciphertext visible, plaintext not)
   - Certificate exchange visible
   - Encrypted messages visible

5. **Save capture** as `securechat_capture.pcap`

## Evidence Checklist

For your assignment submission, include:

- [ ] Wireshark PCAP showing encrypted payloads
- [ ] Screenshots of invalid cert rejection (BAD_CERT)
- [ ] Screenshots of tampering rejection (SIG_FAIL)
- [ ] Screenshots of replay rejection (REPLAY)
- [ ] Transcript file from a session
- [ ] Receipt file with signature
- [ ] Offline verification output showing:
  - Transcript hash verification
  - Receipt signature verification
  - Tampering detection demonstration

## Troubleshooting

**Test fails to connect**:
- Ensure server is running on correct port (default: 3037)
- Check firewall settings

**Certificate errors**:
- Regenerate certificates: `python scripts/gen_ca.py` then `python scripts/gen_cert.py`
- Verify certificates: `python verify_certs.py`

**Transcript not found**:
- Complete a full client session (login, send messages, disconnect)
- Check `transcripts/` directory

