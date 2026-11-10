#!/usr/bin/env python3
"""Create deterministic test copies of the original and rebuilt executables.

Why: the injector ends with `_getwch()` ("press any key"). In a headless session the
console host cannot reliably deliver a key, and _getwch() can consume unrelated console
input, making the differential test flaky. For testing only, the single `call _getwch`
instruction in each test copy is replaced with `mov eax, 120; nop` (120 == 'x'), so the
program exits immediately with the same return value it would produce after pressing 'x'.
Everything else in the image is byte-identical to the shipped binary.

Outputs (gitignored):
    tests/bin/original_noinput.exe   <- original/SKernelInjector.exe
    tests/bin/rebuilt_noinput.exe    <- build/SKernelInjector.exe
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import compare  # noqa: E402

OUT_DIR = ROOT / "tests" / "bin"
KEY_CHAR_CODE = 120                       # 'x'
PATCH = b"\xB8" + struct.pack("<I", KEY_CHAR_CODE) + b"\x90"   # mov eax,120; nop


def patch_getwch(src: Path, dst: Path) -> None:
    pe = compare.PE(src)
    slots = [va for va, name in pe.iat.items() if name == "_getwch"]
    if len(slots) != 1:
        raise SystemExit(f"{src}: expected one _getwch IAT slot, found {slots}")
    needle = b"\xFF\x15" + struct.pack("<I", slots[0])      # call dword ptr [slot]
    text = next(s for s in pe.sections if s[0] == ".text")
    _name, _va, _vs, raw_ptr, raw_size = text
    hits = [i for i in range(raw_ptr, raw_ptr + raw_size)
            if pe.data.startswith(needle, i)]
    if len(hits) != 1:
        raise SystemExit(f"{src}: expected one call _getwch site, found {hits}")
    data = bytearray(pe.data)
    off = hits[0]
    data[off:off + len(PATCH)] = PATCH
    dst.write_bytes(data)
    print(f"patched {src.name} @ file 0x{off:X} -> {dst}")


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    sources = [
        (ROOT / "original" / "SKernelInjector.exe", OUT_DIR / "original_noinput.exe"),
        (ROOT / "build" / "SKernelInjector.exe", OUT_DIR / "rebuilt_noinput.exe"),
    ]
    for src, dst in sources:
        if not src.exists():
            print(f"missing source: {src}", file=sys.stderr)
            return 2
        patch_getwch(src, dst)
    return 0


if __name__ == "__main__":
    sys.exit(main())
