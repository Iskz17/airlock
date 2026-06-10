"""Offline tests for the optional-dependency installer (guard_core.installer).

No real pip/network: we test the pure logic — extras resolution, dry-run command
building, managed-venv path injection (via a fake site-packages dir), and the
status probe. Actual installs are exercised by `airlock-setup` / `/airlock-setup`.
"""
import os
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from guard_core import installer  # noqa: E402

_failures = []


def check(name, cond):
    print(("PASS" if cond else "FAIL"), "-", name)
    if not cond:
        _failures.append(name)


# 1) expand(): names -> packages, 'all' fans out, dedupe, unknown ignored.
check("expand promptguard", installer.expand(["promptguard"]) == installer.EXTRAS["promptguard"]
      and "transformers" in installer.expand(["promptguard"]))
check("expand all covers every extra",
      set(installer.expand(["all"])) == {p for v in installer.EXTRAS.values() for p in v})
check("expand dedupes", installer.expand(["promptguard", "promptguard"]) == installer.EXTRAS["promptguard"])
check("expand pipe/comma + unknown",
      installer.expand(["ocr", "bogus"]) == ["pytesseract", "Pillow"])

# 2) install(dry_run) builds the right intent without running anything.
ok, log = installer.install(["promptguard"], dry_run=True)
check("dry-run ok", ok and "transformers" in log and "would install" in log)
# gated llamafirewall is its own extra, NOT part of `all`
check("all excludes gated llamafirewall", "llamafirewall" not in installer.expand(["all"]))
check("gated extra installs when named", "llamafirewall" in installer.expand(["llamafirewall"]))
ok2, log2 = installer.install(["nope"], dry_run=True)
check("dry-run unknown extras -> not ok", ok2 is False and "no known extras" in log2)

# 3) AIRLOCK_HOME redirects the managed venv location.
with tempfile.TemporaryDirectory() as d:
    os.environ["AIRLOCK_HOME"] = d
    check("venv_dir honors AIRLOCK_HOME", installer.venv_dir() == os.path.join(d, "venv"))

    # 4) add_managed_to_path: a fake venv site-packages becomes importable.
    sp = os.path.join(d, "venv", "lib", "python%d.%d" % sys.version_info[:2], "site-packages")
    os.makedirs(sp)
    with open(os.path.join(sp, "airlock_fake_dep.py"), "w") as f:
        f.write("VALUE = 42\n")
    found = installer.managed_site_packages()
    check("managed_site_packages finds the venv site-packages", found == sp)
    added = installer.add_managed_to_path()
    check("add_managed_to_path returns the dir", added == sp)
    import importlib
    mod = importlib.import_module("airlock_fake_dep")
    check("a dep in the managed venv is importable after path injection", mod.VALUE == 42)

    # 5) status() returns a bool map incl. the tesseract-binary note, never raises.
    st = installer.status()
    check("status has all extras + tesseract note",
          set(st) >= set(installer.EXTRAS) | {"tesseract_binary"}
          and all(isinstance(v, bool) for v in st.values()))

    # cleanup sys.path + module
    if sp in sys.path:
        sys.path.remove(sp)
    sys.modules.pop("airlock_fake_dep", None)
os.environ.pop("AIRLOCK_HOME", None)

# 6) maybe_autostart with everything already-satisfied path is a safe string.
#    (We can't assert "installing" without spawning; assert it never raises and
#     returns a str for an unknown/empty extras spec.)
msg = installer.maybe_autostart("")
check("maybe_autostart returns a string, no raise", isinstance(msg, str))

print()
if _failures:
    print("%d FAILED: %s" % (len(_failures), _failures))
    sys.exit(1)
print("all installer tests passed")
sys.exit(0)
