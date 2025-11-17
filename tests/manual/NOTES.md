# Manual evidence checklist

## Quick Test Commands

1. **Invalid Certificate Test**:
   ```bash
   python tests/manual/test_invalid_cert.py
   ```

2. **Tampering Test**:
   ```bash
   python tests/manual/test_tamper.py
   ```

3. **Replay Test**:
   ```bash
   python tests/manual/test_replay.py
   ```

4. **Non-Repudiation Test**:
   ```bash
   python tests/manual/test_nonrepudiation.py transcripts/<session_id>.json
   ```

5. **Run All Tests**:
   ```bash
   python tests/manual/run_all_tests.py
   ```

## Evidence Checklist

- [ ] Show encrypted payloads (no plaintext) - Use Wireshark
- [ ] BAD_CERT on invalid/self/expired cert - Run test_invalid_cert.py
- [ ] SIG_FAIL on tamper (flip bit in ct) - Run test_tamper.py
- [ ] REPLAY on reused seqno - Run test_replay.py
- [ ] Transcript + signed SessionReceipt - Run test_nonrepudiation.py

See TESTING_GUIDE.md for detailed instructions.
