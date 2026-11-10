#!/usr/bin/env python3
"""Verification report for the SKernelInjector rebuild.

Checks, per the recovery plan:
  1. PE surface: machine, subsystem, sections, DllCharacteristics, load-config GuardFlags.
  2. Exports: names/ordinals (both must have none).
  3. Imports: every original import must be present, except an explicit allowlist of
     codegen-inlined CRT helpers; extras are listed as toolset CRT deltas.
  4. Manifest resource must be byte-identical.
  5. Structural diff of user functions (via tools/compare.py): both user functions must
     be present and their weighted instruction similarity must meet a threshold.
Behavioural testing lives in tests/behavior_test.py.

Usage: python tools/verify.py
Exit code 0 = all hard checks passed.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import compare  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
ORIGINAL = ROOT / "original" / "SKernelInjector.exe"
REBUILT = ROOT / "build" / "SKernelInjector.exe"


def u16(d, o):
    return struct.unpack_from("<H", d, o)[0]


def u32(d, o):
    return struct.unpack_from("<I", d, o)[0]


def cstr(d, o):
    e = d.index(b"\0", o)
    return d[o:e].decode("ascii", "replace")


class Info:
    def __init__(self, path):
        self.path = path
        self.d = path.read_bytes()
        lf = u32(self.d, 0x3C)
        self.lf = lf
        self.coff = lf + 4
        self.opt = self.coff + 20
        self.nsec = u16(self.d, self.coff + 2)
        self.osz = u16(self.d, self.coff + 16)
        self.sec = self.opt + self.osz
        self.sections = []
        for i in range(self.nsec):
            o = self.sec + i * 40
            self.sections.append((
                self.d[o:o + 8].rstrip(b"\0").decode("ascii", "replace"),
                u32(self.d, o + 8), u32(self.d, o + 12),
                u32(self.d, o + 16), u32(self.d, o + 20),
                u32(self.d, o + 36),
            ))
        self.machine = u16(self.d, self.coff)
        self.subsystem = u16(self.d, self.opt + 68)
        self.dllchar = u16(self.d, self.opt + 70)
        self.subsys_ver = (u16(self.d, self.opt + 48), u16(self.d, self.opt + 50))
        self.dirs = []
        for i in range(16):
            self.dirs.append((u32(self.d, self.opt + 96 + i * 8),
                              u32(self.d, self.opt + 100 + i * 8)))
        self.imports = self._imports()
        self.exports = self._exports()
        self.manifest = self._resource(24, 1)
        self.guard_flags = self._guard_flags()

    def off(self, rva):
        # sections are stored as (name, vsize, vaddr, rawsize, rawptr, chars)
        for _n, vs, va, rs, rp, _c in self.sections:
            if va <= rva < va + max(vs, rs):
                return rp + (rva - va)
        return None

    def _imports(self):
        rva, size = self.dirs[1]
        out = set()
        if not rva:
            return out
        o = self.off(rva)
        while o is not None:
            ilt = u32(self.d, o)
            name_rva = u32(self.d, o + 12)
            first = u32(self.d, o + 16)
            if ilt == 0 and name_rva == 0 and first == 0:
                break
            dll = cstr(self.d, self.off(name_rva))
            thunk = self.off(ilt or first)   # ILT may be absent; fall back to IAT
            while thunk is not None:
                val = u32(self.d, thunk)
                if val == 0:
                    break
                if not (val & 0x80000000):
                    nmo = self.off(val)
                    out.add((dll, self.d[nmo + 2:nmo + 2 + 128].split(b"\0", 1)[0].decode("ascii", "replace")))
                thunk += 4
            o += 20
        return out

    def _exports(self):
        rva, size = self.dirs[0]
        if not rva:
            return []
        o = self.off(rva)
        nfuncs = u32(self.d, o + 20)
        nnames = u32(self.d, o + 24)
        funcs_rva = u32(self.d, o + 28)
        names_rva = u32(self.d, o + 32)
        ords_rva = u32(self.d, o + 36)
        no = self.off(names_rva)
        fo = self.off(funcs_rva)
        oo = self.off(ords_rva)
        out = []
        for i in range(nnames):
            nm = cstr(self.d, self.off(u32(self.d, no + i * 4)))
            ordinal = u16(self.d, oo + i * 2)      # index into the EAT
            frva = u32(self.d, fo + ordinal * 4)
            out.append((nm, ordinal, frva))
        return out

    def _resource(self, rtype, rid):
        rva, size = self.dirs[2]
        if not rva:
            return None
        base = self.off(rva)

        def leaves(off, path):
            n_named = u16(self.d, off + 12)
            n_id = u16(self.d, off + 14)
            for i in range(n_named + n_id):
                e = off + 16 + i * 8
                name = u32(self.d, e)
                target = u32(self.d, e + 4)
                if target & 0x80000000:
                    yield from leaves(base + (target & 0x7FFFFFFF), path + [name])
                else:
                    yield path + [name], target

        for path, target in leaves(base, []):
            if len(path) >= 2 and path[0] == rtype and path[1] == rid:
                data = base + target
                drva = u32(self.d, data)
                dsize = u32(self.d, data + 4)
                off = self.off(drva)
                return self.d[off:off + dsize]
        return None

    def _guard_flags(self):
        rva, size = self.dirs[10]
        if not rva:
            return None
        o = self.off(rva)
        return u32(self.d, o + 0x58) if u32(self.d, o) >= 0x5C else None


def main():
    if not REBUILT.exists():
        print(f"missing rebuilt binary: {REBUILT}")
        return 2
    a = Info(ORIGINAL)
    b = Info(REBUILT)
    failures = []

    def check(cond, label, detail=""):
        print(f"  [{'PASS' if cond else 'FAIL'}] {label}{(' - ' + detail) if detail else ''}")
        if not cond:
            failures.append(label)

    print("== PE surface ==")
    check(a.machine == b.machine == 0x14C, "machine i386")
    check(a.subsystem == b.subsystem == 3, "subsystem console")
    check(a.subsys_ver == b.subsys_ver, "subsystem version", f"{a.subsys_ver} vs {b.subsys_ver}")
    check(a.dllchar == b.dllchar, "DllCharacteristics", hex(a.dllchar) + " vs " + hex(b.dllchar))
    check([s[0] for s in a.sections] == [s[0] for s in b.sections],
          "section names", str([s[0] for s in a.sections]))
    check(a.guard_flags == b.guard_flags, "load-config GuardFlags",
          hex(a.guard_flags or 0) + " vs " + hex(b.guard_flags or 0))

    print("\n== exports ==")
    check(a.exports == b.exports == [], "no exports in either image")

    print("\n== imports ==")
    missing = sorted(a.imports - b.imports)
    extra = sorted(b.imports - a.imports)
    # Explicit, reviewed allowlist: helpers the newer compiler inlines away instead of
    # importing (the operation is still performed, just inline).
    ALLOWED_MISSING = {("VCRUNTIME140.dll", "memcpy")}
    missing_unexpected = [m for m in missing if m not in ALLOWED_MISSING]
    check(not missing_unexpected,
          f"all original imports present ({len(a.imports)} checked; "
          f"allowlisted codegen deltas: {sorted(ALLOWED_MISSING)})",
          str(missing_unexpected))
    print(f"  [INFO] {len(extra)} toolset/CRT-only extras: {extra}")

    print("\n== manifest ==")
    check(a.manifest == b.manifest, "RT_MANIFEST byte-identical",
          f"{len(a.manifest or b'')} vs {len(b.manifest or b'')} bytes")

    print("\n== structural diff (user functions) ==")
    MIN_USER_SIM = 85.0
    build_dir = REBUILT.parent
    funcs = compare.parse_map(build_dir / "SKernelInjector.map")
    new_targets = compare.new_target_map(funcs)
    found_user = set()
    weight = score = 0.0
    try:
        orig_pe = compare.PE(ORIGINAL)
        new_pe = compare.PE(REBUILT)
        for disp, ostart, oend, symbol in compare.ORIGINAL_FUNCS:
            if symbol not in funcs:
                continue
            nstart, nsize = funcs[symbol]
            m = compare.score_function(orig_pe, new_pe, ostart, oend, nstart, nsize,
                                       new_targets)
            print(f"  {disp:42s} size 0x{m['orig_size']:03X} vs 0x{m['new_size']:03X}  "
                  f"LCS {m['ins_sim']:5.1f}%  calls {m['call_sim']:5.1f}%")
            if disp in compare.USER_FUNCS:
                found_user.add(disp)
                weight += oend - ostart
                score += m["ins_sim"] * (oend - ostart)
    except RuntimeError as exc:
        check(False, "structural diff available", str(exc))
        weight = 0.0
    required = set(compare.USER_FUNCS)
    check(required <= found_user, "both user functions present in rebuild map",
          f"missing: {sorted(required - found_user)}")
    if weight:
        sim = score / weight
        print(f"  weighted user-code instruction similarity: {sim:.1f}%")
        check(sim >= MIN_USER_SIM,
              f"user-code structural similarity >= {MIN_USER_SIM:.0f}%", f"{sim:.1f}%")
    else:
        check(False, "user-code structural similarity computable", "no user functions scored")
    print("  NOTE: main's residual delta is toolset inlining/scheduling (see README).")

    print("\n== result ==")
    if failures:
        print(f"FAILED checks: {failures}")
        return 1
    print("All hard checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
