"""Run every airlock test suite; exit nonzero if any suite fails."""
import pathlib
import subprocess
import sys

_HERE = pathlib.Path(__file__).resolve().parent
_SUITES = ["test_core.py", "test_egress.py", "test_more.py", "test_mcp.py",
           "test_alignment.py", "test_server.py", "test_persistence.py", "test_installer.py",
           "test_redteam_fixes.py"]


def main():
    rc = 0
    for suite in _SUITES:
        print("=" * 64)
        print("RUN", suite)
        print("=" * 64, flush=True)  # flush so headers precede child output when piped
        result = subprocess.run([sys.executable, str(_HERE / suite)])
        rc = rc or result.returncode
        print()
    print("=== SUMMARY:", "ALL PASSED" if rc == 0 else "FAILURES PRESENT", "===")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
