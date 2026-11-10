#!/usr/bin/env python3
"""Behavioral differential test: original vs rebuilt SKernelInjector.exe.

Both executables request administrator in their manifest, so they are launched with
__COMPAT_LAYER=RunAsInvoker (the manifest is not part of the recovered logic).  Each
process gets its own console; stdout/stderr are piped.  Once the injector is waiting in
_getwch(), a key event ('x', VK 0x58) is written to its console input buffer, which makes
main return the key code.  Output and exit code are then compared byte-for-byte.

Scenarios:
  1. "game absent"  - no left4dead2.exe running -> pid lookup fails, injection fails.
  2. "game present" - tests/bin/left4dead2.exe (dummy) running -> full injection path,
                      LoadLibraryA fails inside the dummy (no VR.dll) but the remote
                      thread is created, so the success message is expected.

Usage: python tests/behavior_test.py
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ORIGINAL = ROOT / "original" / "SKernelInjector.exe"
REBUILT = ROOT / "build" / "SKernelInjector.exe"
DUMMY = ROOT / "tests" / "bin" / "left4dead2.exe"
RUNDIR = ROOT / "tests" / "run_dir"

CREATE_NEW_CONSOLE = 0x00000010
STD_INPUT_HANDLE = -10
KEY_EVENT = 0x0001

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
kernel32.AttachConsole.argtypes = [wt.DWORD]
kernel32.AttachConsole.restype = wt.BOOL
kernel32.FreeConsole.argtypes = []
kernel32.FreeConsole.restype = wt.BOOL
kernel32.CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p,
                                 wt.DWORD, wt.DWORD, wt.HANDLE]
kernel32.CreateFileW.restype = wt.HANDLE
kernel32.CloseHandle.argtypes = [wt.HANDLE]
kernel32.WriteConsoleInputW.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD)]
kernel32.WriteConsoleInputW.restype = wt.BOOL


class KEY_EVENT_RECORD(ctypes.Structure):
    _fields_ = [
        ("bKeyDown", wt.BOOL),
        ("wRepeatCount", wt.WORD),
        ("wVirtualKeyCode", wt.WORD),
        ("wVirtualScanCode", wt.WORD),
        ("UnicodeChar", wt.WCHAR),
        ("dwControlKeyState", wt.DWORD),
    ]


class _EVENT(ctypes.Union):
    _fields_ = [("KeyEvent", KEY_EVENT_RECORD)]


class INPUT_RECORD(ctypes.Structure):
    _anonymous_ = ("Event",)
    _fields_ = [("EventType", wt.WORD), ("Event", _EVENT)]


def press_key(pid: int, ch: str = "x") -> bool:
    kernel32.FreeConsole()
    if not kernel32.AttachConsole(pid):
        return False
    try:
        # GetStdHandle() still returns the (now stale) handles of the previous console,
        # so open the attached console's input buffer explicitly.
        h = kernel32.CreateFileW("CONIN$", 0x80000000 | 0x40000000, 3, None, 3, 0, None)
        if not h or h == wt.HANDLE(-1).value:
            return False
        try:
            vk = ord(ch.upper())
            recs = (INPUT_RECORD * 2)()
            for i, down in enumerate((True, False)):
                recs[i].EventType = KEY_EVENT
                recs[i].KeyEvent.bKeyDown = down
                recs[i].KeyEvent.wRepeatCount = 1
                recs[i].KeyEvent.wVirtualKeyCode = vk
                recs[i].KeyEvent.wVirtualScanCode = 0x2D
                recs[i].KeyEvent.UnicodeChar = ch
                recs[i].KeyEvent.dwControlKeyState = 0
            written = wt.DWORD(0)
            return bool(kernel32.WriteConsoleInputW(h, ctypes.byref(recs),
                                                    len(recs), ctypes.byref(written)))
        finally:
            kernel32.CloseHandle(h)
    finally:
        kernel32.FreeConsole()


def run_injector(exe: Path, attempts: int = 5, wait_before_key: float = 1.0,
                 timeout: float = 20.0):
    """Run one injector and feed it a key. The CREATE_NEW_CONSOLE console setup races
    with _getwch() in headless sessions, so retry until a clean run is obtained."""
    env = dict(os.environ)
    env["__COMPAT_LAYER"] = "RunAsInvoker"
    last = (None, None, False, "NO ATTEMPT")
    for _attempt in range(attempts):
        p = subprocess.Popen(
            [str(exe)],
            cwd=str(RUNDIR),
            stdin=subprocess.PIPE,      # keep an owned handle; _getwch() uses CONIN$
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            creationflags=CREATE_NEW_CONSOLE,
            env=env,
        )
        time.sleep(wait_before_key)
        if p.poll() is not None:        # exited before we could attach: console race
            out = p.stdout.read()
            p.wait()
            last = (out, p.returncode, False, "EARLY EXIT")
            continue
        keyed = press_key(p.pid)
        try:
            out, _ = p.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            p.kill()
            out, _ = p.communicate()
            last = (out, None, keyed, "TIMEOUT")
            continue
        result = (out, p.returncode, keyed, None)
        if keyed and p.returncode == 120:   # 'x' delivered and returned by main
            return result
        last = result
    return last


def run_case(name: str, dummy: subprocess.Popen | None):
    print(f"\n=== scenario: {name} ===")
    if dummy:
        time.sleep(0.7)  # let the dummy appear in Toolhelp32
    results = []
    for label, exe in (("original", ORIGINAL), ("rebuilt", REBUILT)):
        out, code, keyed, err = run_injector(exe)
        results.append((label, out, code, keyed, err))
        status = "ok" if err is None else err
        print(f"  {label:9s}: exit={code} key_injected={keyed} {status}")
        if out:
            print("    " + out.decode("utf-8", "replace").replace("\n", "\n    ").rstrip())
    (l1, o1, c1, k1, e1), (l2, o2, c2, k2, e2) = results
    same_out = o1 == o2
    same_code = c1 == c2
    print(f"  output identical: {same_out}; exit code identical: {same_code}")
    if not same_out:
        import difflib
        d = difflib.unified_diff(o1.decode("utf-8", "replace").splitlines(),
                                 o2.decode("utf-8", "replace").splitlines(),
                                 fromfile=l1, tofile=l2, lineterm="")
        print("\n".join(d))
    if dummy:
        dummy.kill()
        dummy.wait()
    ok = same_out and same_code and k1 and k2 and e1 is None and e2 is None
    print(f"  RESULT: {'PASS' if ok else 'FAIL'}")
    return ok


def main() -> int:
    RUNDIR.mkdir(parents=True, exist_ok=True)
    for exe in (ORIGINAL, REBUILT, DUMMY):
        if not exe.exists():
            print(f"missing: {exe}", file=sys.stderr)
            return 2
    ok1 = run_case("game absent", None)
    dummy = subprocess.Popen([str(DUMMY)], cwd=str(RUNDIR))
    try:
        ok2 = run_case("game present (dummy)", dummy)
    finally:
        if dummy.poll() is None:
            dummy.kill()
    print(f"\nOVERALL: {'PASS' if (ok1 and ok2) else 'FAIL'}")
    return 0 if (ok1 and ok2) else 1


if __name__ == "__main__":
    sys.exit(main())
