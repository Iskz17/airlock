"""Optional-dependency installer for the heavier stages.

The guard core is stdlib-only and works the moment airlock is installed. The
heavier detectors are opt-in (Stage 2 Prompt Guard 2 pulls PyTorch + a model;
Stage 2b needs OCR; Stage 6 enrichment needs mcp-scan). Rather than make the
user hand-run pip — or, worse, silently download gigabytes at session start —
this installs them on request into an **isolated venv airlock manages**
(`~/.cache/airlock/venv`, override with `AIRLOCK_HOME`). It is:

  * **explicit** — triggered by `/airlock-setup`, the `airlock-setup` CLI, or the
    opt-in `AIRLOCK_AUTO_INSTALL=1`; never silent;
  * **isolated** — never touches the user's system/site Python; uninstall by
    deleting the venv directory;
  * **fail-open** — any failure is reported, never raised into the host session.

`add_managed_to_path()` puts the managed venv on `sys.path` so the lazy imports
in scanners/multimodal/mcp_vetting pick the deps up in later sessions. The venv
is created with the SAME interpreter the hooks run under, so wheels match.
"""
from __future__ import annotations

import glob
import importlib.util
import os
import subprocess
import sys
import time

# extra-name -> pip package list (mirrors pyproject [project.optional-dependencies])
EXTRAS = {
    "promptguard": ["llamafirewall"],                       # Stage 2 / Stage 3
    "pii": ["presidio-analyzer", "presidio-anonymizer"],    # Stage 4 richer PII
    "ocr": ["pytesseract", "Pillow"],                       # Stage 2b (also needs the tesseract binary)
    "mcp": ["mcp-scan"],                                    # Stage 6 enrichment
}
# extra-name -> import name used to probe whether it's already present
_PROBE = {"promptguard": "llamafirewall", "pii": "presidio_analyzer",
          "ocr": "pytesseract", "mcp": "mcp_scan"}

_pkg_parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def home():
    return os.environ.get("AIRLOCK_HOME") or os.path.join(
        os.path.expanduser("~"), ".cache", "airlock")


def venv_dir():
    return os.path.join(home(), "venv")


def managed_site_packages(venv=None):
    venv = venv or venv_dir()
    cands = glob.glob(os.path.join(venv, "lib", "python*", "site-packages"))
    cands.append(os.path.join(venv, "Lib", "site-packages"))  # Windows
    for c in cands:
        if os.path.isdir(c):
            return c
    return None


def add_managed_to_path():
    """Prepend the managed venv's site-packages to sys.path (idempotent). Returns
    the path if present, else None. Cheap; safe to call before optional imports."""
    try:
        sp = managed_site_packages()
    except Exception:
        return None
    if sp and sp not in sys.path:
        sys.path.insert(0, sp)
    return sp


def expand(extras):
    """Resolve a list of extra names (incl. 'all') to a deduped pip package list."""
    pkgs = []
    for e in extras:
        e = (e or "").strip().lower()
        if not e:
            continue
        if e == "all":
            for v in EXTRAS.values():
                pkgs.extend(v)
        else:
            pkgs.extend(EXTRAS.get(e, []))
    seen, out = set(), []
    for p in pkgs:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def _venv_python(venv=None):
    venv = venv or venv_dir()
    for rel in ("bin/python", "bin/python3", "Scripts/python.exe"):
        p = os.path.join(venv, rel)
        if os.path.exists(p):
            return p
    return None


def ensure_venv(venv=None):
    venv = venv or venv_dir()
    py = _venv_python(venv)
    if py:
        return py
    os.makedirs(os.path.dirname(venv) or ".", exist_ok=True)
    subprocess.run([sys.executable, "-m", "venv", venv], check=True,
                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return _venv_python(venv)


def install(extras, dry_run=False, timeout=1800):
    """Install the given extras into the managed venv.
    Returns (ok: bool, log: str). Never raises."""
    pkgs = expand(extras)
    if not pkgs:
        return False, "no known extras in %r (valid: %s, all)" % (extras, ", ".join(EXTRAS))
    if dry_run:
        return True, "would install into %s: %s" % (venv_dir(), " ".join(pkgs))
    try:
        py = ensure_venv()
        if not py:
            return False, "could not create managed venv at %s" % venv_dir()
        cmd = [py, "-m", "pip", "install", "--upgrade"] + pkgs
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              timeout=timeout, text=True)
        return proc.returncode == 0, (proc.stdout or "")[-4000:]
    except subprocess.TimeoutExpired:
        return False, "install timed out after %ss" % timeout
    except Exception as e:  # noqa: BLE001 — fail open
        return False, "install failed: %s" % e


def status():
    """Which extras are importable (managed venv + base env), plus binary notes."""
    add_managed_to_path()
    out = {}
    for extra, mod in _PROBE.items():
        try:
            out[extra] = importlib.util.find_spec(mod) is not None
        except Exception:
            out[extra] = False
    # Stage 2b also needs the system tesseract binary; flag it honestly.
    import shutil
    out["tesseract_binary"] = shutil.which("tesseract") is not None
    return out


def _lock_path():
    return venv_dir() + ".install.lock"


def maybe_autostart(extras_str, max_lock_age=3600):
    """For AIRLOCK_AUTO_INSTALL: kick off a background install if needed.
    Returns a short human status string for the SessionStart line. Non-blocking."""
    extras = [e for e in (extras_str or "promptguard").replace("|", ",").split(",") if e.strip()]
    want = set(expand(extras))
    if not want:
        return ""
    st = status()
    needed = []
    for e in extras:
        if e == "all":
            if not all(status().get(k) for k in EXTRAS):
                needed.append(e)
        elif not st.get(e):
            needed.append(e)
    if not needed:
        return "extras already installed"

    lock = _lock_path()
    try:
        if os.path.exists(lock) and (time.time() - os.path.getmtime(lock)) < max_lock_age:
            return "dependency install already in progress"
        os.makedirs(os.path.dirname(lock) or ".", exist_ok=True)
        with open(lock, "w") as f:
            f.write(str(int(time.time())))
        logf = open(os.path.join(home(), "install.log"), "a")
        env = dict(os.environ)
        env["PYTHONPATH"] = _pkg_parent + os.pathsep + env.get("PYTHONPATH", "")
        subprocess.Popen(
            [sys.executable, "-m", "guard_core.installer", "--extras", ",".join(needed), "--release-lock"],
            stdout=logf, stderr=logf, env=env, start_new_session=True)
        return "installing %s in background (active next session)" % ",".join(needed)
    except Exception as e:  # noqa: BLE001
        return "auto-install could not start: %s" % e


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    extras = ["promptguard"]
    dry = "--dry-run" in argv
    release_lock = "--release-lock" in argv
    if "--status" in argv:
        import json
        sys.stdout.write(json.dumps(status(), indent=2) + "\n")
        return 0
    if "--extras" in argv:
        i = argv.index("--extras")
        if i + 1 < len(argv):
            extras = [e for e in argv[i + 1].replace("|", ",").split(",") if e.strip()]

    ok, log = install(extras, dry_run=dry)
    if release_lock:
        try:
            os.remove(_lock_path())
        except OSError:
            pass
    sys.stdout.write(log.rstrip() + "\n")
    import json
    sys.stdout.write("airlock extras status: %s\n" % json.dumps(status()))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
