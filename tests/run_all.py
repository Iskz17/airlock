"""Run every airlock test suite; exit nonzero if any suite fails."""
import os
import pathlib
import subprocess
import sys
import tempfile

_HERE = pathlib.Path(__file__).resolve().parent
_SUITES = ["test_core.py", "test_egress.py", "test_more.py", "test_mcp.py",
           "test_alignment.py", "test_server.py", "test_persistence.py", "test_installer.py",
           "test_redteam_fixes.py", "test_stage2.py"]


def main():
    rc = 0
    # Hermetic: point AIRLOCK_HOME at an empty dir so add_managed_to_path() can't
    # pull a locally-installed managed venv (Stage 2 ML model, etc.) onto sys.path
    # and make the offline suite non-deterministic. Mirrors a clean CI runner.
    env = dict(os.environ)
    env["AIRLOCK_HOME"] = tempfile.mkdtemp(prefix="airlock-test-home-")
    for suite in _SUITES:
        print("=" * 64)
        print("RUN", suite)
        print("=" * 64, flush=True)  # flush so headers precede child output when piped
        result = subprocess.run([sys.executable, str(_HERE / suite)], env=env)
        rc = rc or result.returncode
        print()
    print("=== SUMMARY:", "ALL PASSED" if rc == 0 else "FAILURES PRESENT", "===")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
