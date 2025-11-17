"""Run all security tests."""

import sys
import time
import subprocess

def run_test(test_name, test_file, *args):
    """Run a test and return success status."""
    print(f"\n{'='*70}")
    print(f"Running: {test_name}")
    print('='*70)
    
    try:
        cmd = ["python", test_file] + list(args)
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        print(result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr, file=sys.stderr)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        print(f"✗ Test timed out: {test_name}")
        return False
    except Exception as e:
        print(f"✗ Error running test: {e}")
        return False


def main():
    """Run all tests."""
    host = sys.argv[1] if len(sys.argv) > 1 else "localhost"
    port = sys.argv[2] if len(sys.argv) > 2 else "3037"
    
    print("="*70)
    print("SECURE CHAT - SECURITY TEST SUITE")
    print("="*70)
    print(f"\nTarget: {host}:{port}")
    print("\nIMPORTANT: Make sure the server is running before starting tests!")
    print("  Start server: python -m app.server")
    print("\nPress Enter to continue or Ctrl+C to cancel...")
    try:
        input()
    except KeyboardInterrupt:
        print("\nCancelled.")
        return
    
    results = {}
    
    # Test 1: Invalid Certificate
    results["Invalid Cert"] = run_test(
        "Invalid Certificate Test (BAD_CERT)",
        "tests/manual/test_invalid_cert.py",
        host, port
    )
    time.sleep(1)
    
    # Test 2: Tampering
    results["Tampering"] = run_test(
        "Tampering Test (SIG_FAIL)",
        "tests/manual/test_tamper.py",
        host, port
    )
    time.sleep(1)
    
    # Test 3: Replay
    results["Replay"] = run_test(
        "Replay Test (REPLAY)",
        "tests/manual/test_replay.py",
        host, port
    )
    time.sleep(1)
    
    # Test 4: Non-repudiation (requires transcript file)
    print("\n" + "="*70)
    print("Non-Repudiation Test")
    print("="*70)
    print("\nThis test requires a transcript file from a previous session.")
    print("If you have a transcript, specify it as an argument:")
    print("  python tests/manual/test_nonrepudiation.py transcripts/<session_id>.json")
    print("\nSkipping for now (run manually after generating a transcript).")
    results["Non-repudiation"] = None
    
    # Summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    
    for test_name, passed in results.items():
        if passed is None:
            status = "SKIPPED"
        elif passed:
            status = "✓ PASSED"
        else:
            status = "✗ FAILED"
        print(f"  {test_name:20s}: {status}")
    
    print("="*70)


if __name__ == "__main__":
    main()

