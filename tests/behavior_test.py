#!/usr/bin/env python3
"""Behavioral differential test: original vs rebuilt SKernelInjector.exe.

Deterministic by construction: both executables end in `_getwch()` ("press any key"),
which cannot be fed reliably from a headless harness. `tests/make_test_copies.py`
therefore creates test copies whose single `call _getwch` site is replaced with
`mov eax, 120; nop` (120 == 'x'); everything else is byte-identical. This test then runs
each copy normally and compares stdout, exit code (120) and the expected branch.

Scenarios:
  1. "game absent"  - no left4dead2.exe running -> pid lookup fails, injection fails.
  2. "game present" - a fresh tests/bin/left4dead2.exe dummy per executable -> full
                      injection path; LoadLibraryA fails inside the dummy (no VR.dll) but
                      the remote thread is created, so the success banner is expected.

Safety: if a real left4dead2.exe is already running, the suite refuses to run rather
than injecting into the user's game.

Usage: python tests/behavior_test.py
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
import make_test_copies  # noqa: E402

ORIGINAL_SRC = ROOT / "original" / "SKernelInjector.exe"
REBUILT_SRC = ROOT / "build" / "SKernelInjector.exe"
ORIGINAL = ROOT / "tests" / "bin" / "original_noinput.exe"
REBUILT = ROOT / "tests" / "bin" / "rebuilt_noinput.exe"
DUMMY = ROOT / "tests" / "bin" / "left4dead2.exe"
RUNDIR = ROOT / "tests" / "run_dir"

KEY_CHAR_CODE = 120          # 'x' - main() returns the _getwch() key code
RUN_TIMEOUT = 30.0


def ensure_test_copies() -> None:
    """Regenerate patched test copies if missing or older than their sources."""
    OUT = ORIGINAL.parent
    need = False
    for src, dst in ((ORIGINAL_SRC, ORIGINAL), (REBUILT_SRC, REBUILT)):
        if not dst.exists() or dst.stat().st_mtime < src.stat().st_mtime:
            need = True
    if need:
        if make_test_copies.main() != 0:
            raise SystemExit("failed to create patched test copies")


def left4dead2_running() -> bool:
    """True if any process with image name left4dead2.exe is alive."""
    try:
        out = subprocess.run(["tasklist", "/FI", "IMAGENAME eq left4dead2.exe", "/NH"],
                             capture_output=True, text=True, timeout=20).stdout
    except (OSError, subprocess.TimeoutExpired):
        return False
    return "left4dead2.exe" in out.casefold()


def run_injector(exe: Path):
    """Run a patched test copy to completion; return (stdout, exit_code)."""
    env = dict(os.environ)
    env["__COMPAT_LAYER"] = "RunAsInvoker"     # manifest requests elevation
    p = subprocess.run(
        [str(exe)],
        cwd=str(RUNDIR),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=RUN_TIMEOUT,
        env=env,
    )
    return p.stdout, p.returncode


def run_case(name: str, expect_success: bool, start_dummy: bool) -> bool:
    print(f"\n=== scenario: {name} ===")
    results = []
    for label, exe in (("original", ORIGINAL), ("rebuilt", REBUILT)):
        dummy = None
        if start_dummy:
            dummy = subprocess.Popen([str(DUMMY)], cwd=str(RUNDIR))
            time.sleep(0.7)
            if dummy.poll() is not None:
                print("  FAIL: dummy left4dead2.exe exited before the injector ran")
                return False
        try:
            out, code = run_injector(exe)
        except subprocess.TimeoutExpired:
            out, code = None, None
        finally:
            if dummy and dummy.poll() is None:
                dummy.kill()
                dummy.wait()
        results.append((label, out, code))
        print(f"  {label:9s}: exit={code}")
        if out:
            print("    " + out.decode("utf-8", "replace").replace("\n", "\n    ").rstrip())

    (l1, o1, c1), (l2, o2, c2) = results
    same_out = o1 is not None and o1 == o2
    same_code = c1 == c2 == KEY_CHAR_CODE
    if o1 is not None and expect_success:
        branch_ok = (b"Successfully injected" in o1
                     and b"Failed getting left4dead2.exe process ID" not in o1)
    elif o1 is not None:
        branch_ok = (b"Failed getting left4dead2.exe process ID" in o1
                     and b"Injection failed!" in o1
                     and b"Successfully injected" not in o1)
    else:
        branch_ok = False

    print(f"  output identical: {same_out}; exit code == {KEY_CHAR_CODE}: {same_code}; "
          f"expected branch: {branch_ok}")
    if not same_out and o1 is not None and o2 is not None:
        import difflib
        d = difflib.unified_diff(o1.decode("utf-8", "replace").splitlines(),
                                 o2.decode("utf-8", "replace").splitlines(),
                                 fromfile=l1, tofile=l2, lineterm="")
        print("\n".join(d))
    ok = same_out and same_code and branch_ok
    print(f"  RESULT: {'PASS' if ok else 'FAIL'}")
    return ok


def main() -> int:
    RUNDIR.mkdir(parents=True, exist_ok=True)
    for exe in (ORIGINAL_SRC, REBUILT_SRC):
        if not exe.exists():
            print(f"missing: {exe}", file=sys.stderr)
            return 2
    ensure_test_copies()
    if not DUMMY.exists():
        print(f"missing: {DUMMY}\nbuild it first: tests\\build_dummy.bat", file=sys.stderr)
        return 2
    if left4dead2_running():
        print("REFUSING TO RUN: a real left4dead2.exe is already running. "
              "Close the game before running this test.", file=sys.stderr)
        return 3
    ok1 = run_case("game absent", expect_success=False, start_dummy=False)
    if left4dead2_running():   # our dummies are killed; a real game appeared meanwhile
        print("REFUSING TO CONTINUE: left4dead2.exe appeared during the test.",
              file=sys.stderr)
        return 3
    ok2 = run_case("game present (dummy)", expect_success=True, start_dummy=True)
    print(f"\nOVERALL: {'PASS' if (ok1 and ok2) else 'FAIL'}")
    return 0 if (ok1 and ok2) else 1


if __name__ == "__main__":
    sys.exit(main())
