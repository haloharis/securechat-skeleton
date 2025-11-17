# Grading Rubric Checklist

## 1. GitHub Workflow (20%)
- [x] Fork accessible
- [ ] ≥10 clear commits (need to check git log)
- [ ] Sensible README (exists but may need updates)
- [x] Proper .gitignore (created)
- [x] No secrets committed (gitignore protects .env, *.key, etc.)

**Status**: ⚠️ Need to verify commits and update README

## 2. PKI Setup & Certificates (20%)
- [x] Root CA works (gen_ca.py implemented)
- [x] Server & client certs issued (gen_cert.py implemented)
- [x] Mutual verification (client validates server, server validates client)
- [x] Expiry checks (implemented in pki.py)
- [x] Hostname/CN checks (implemented in pki.py)
- [x] Invalid/self-signed/expired certs rejected (BAD_CERT error)

**Status**: ✅ EXCELLENT - All requirements met

## 3. Registration & Login Security (20%)
- [x] Per-user random salt ≥16B (secrets.token_bytes(16))
- [x] Store hex(sha256(salt||pwd)) (implemented correctly)
- [⚠️] Credentials sent AFTER cert checks ✓ (handshake first)
- [❌] Credentials sent UNDER encryption ✗ (register/login sent in plaintext after DH)
- [x] No plaintext passwords in files/logs
- [❌] Constant-time compare ✗ (using == comparison)

**Issues**:
- ❌ Register/Login should be encrypted (currently plaintext after DH)
- ❌ Need constant-time password comparison to prevent timing attacks

**Status**: ⚠️ GOOD - Need encryption for auth and constant-time compare

## 4. Encrypted Chat (AES-128) (20%)
- [⚠️] DH after login ✗ (currently DH happens BEFORE login in handshake)
- [x] K = Trunc16(SHA256(Ks)) (derive_aes_key implemented correctly)
- [x] AES-128 used correctly (implemented in aes.py)
- [x] PKCS#7 padding (implemented correctly)
- [x] Clean send/receive path
- [x] Clear error handling

**Issues**:
- ❌ DH should happen AFTER login, not before (per rubric)

**Status**: ⚠️ GOOD - DH timing needs adjustment per spec

## 5. Integrity, Authenticity & Non-Repudiation (10%)
- [❌] Message digest: h = SHA256(seqno∥ts∥ct) ✗ (currently: SHA256(seqno:ct) - missing timestamp)
- [⚠️] RSA-sign h ✓ (implemented but verification disabled)
- [❌] Verify every message ✗ (signature verification commented out in server)
- [x] Strict replay defense on seqno (duplicate + ordering checks)
- [x] Append-only transcript (implemented)
- [x] SessionReceipt with signed transcript hash (implemented)
- [x] Receipt exported (saved to transcripts/ directory)
- [⚠️] Offline verification documented (needs documentation)

**Issues**:
- ❌ Message digest missing timestamp (should be seqno∥ts∥ct)
- ❌ Signature verification disabled on server side
- ⚠️ Need offline verification documentation

**Status**: ⚠️ GOOD - Need timestamp in digest and enable signature verification

## 6. Testing & Evidence (10%)
- [ ] PCAP/screenshots showing encrypted payloads
- [ ] Filters included
- [ ] Invalid/expired cert rejection shown
- [ ] Tamper + replay tests shown
- [ ] Steps reproducible by TA
- [ ] Test documentation

**Status**: ❌ BAD - No evidence documented yet

## Summary

**Current Grade Estimate**: GOOD (7/10) - Needs fixes for EXCELLENT

### Critical Fixes Needed:
1. **Move DH key exchange AFTER login** (not in initial handshake)
2. **Encrypt register/login messages** using established encryption
3. **Add timestamp to message digest**: SHA256(seqno∥ts∥ct) instead of seqno:ct
4. **Enable signature verification** on server (currently commented out)
5. **Implement constant-time password comparison**
6. **Create test evidence** (PCAPs, screenshots, documentation)

### Minor Improvements:
- Update README with setup instructions and test evidence
- Ensure ≥10 meaningful git commits
- Document offline verification procedure


