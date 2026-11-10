#!/usr/bin/env python3
"""Structural comparison of original vs rebuilt SKernelInjector.exe.

- Extracts per-function instruction streams with objdump (MinGW binutils; must be on
  PATH - see README "Prerequisites").
- Normalizes addresses (IAT slots -> import names, internal targets -> symbols,
  other absolute addresses -> ADDR) while keeping constants/stack offsets.
- Scores each function with an LCS ratio over normalized instructions and
  over mnemonic sequences; reports sizes, instruction counts, branch counts.

Usage: python tools/compare.py [build_dir]     (default: build)
"""
from __future__ import annotations

import re
import shutil
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OBJDUMP = (
    shutil.which("objdump")
    or shutil.which("objdump", path=r"C:\MinGW\bin")
    or "objdump"
)

# Canonical names for call-target normalisation (original VAs).
ORIG_STARTS = {
    0x401000: "main", 0x4012C0: "__local_stdio_printf_options",
    0x4012D0: "printf", 0x401300: "GetProcessId",
    0x4013E0: "_Xlength_error", 0x4013F0: "std_exception_ctor",
    0x401410: "std_exception_dtor", 0x401430: "std_exception_deleting_dtor",
    0x401470: "bad_array_new_length_copy_ctor", 0x4014B0: "bad_alloc_copy_ctor",
    0x4014F0: "exception_what", 0x401500: "exception_copy_ctor",
    0x401530: "throw_bad_array_new_length", 0x401550: "string_assign",
    0x401680: "__security_check_cookie", 0x40168E: "operator_delete",
    0x40169C: "operator_new", 0x4016CC: "sub_4016CC",
    0x4016EF: "pre_c_initialization", 0x4017B4: "__scrt_common_main_seh",
    0x401936: "start", 0x401940: "__raise_securityfailure",
    0x401968: "__report_gsfailure", 0x401A62: "j_free", 0x401A9C: "find_pe_section",
}

# Rebuilt mangled symbol -> canonical name.
SYMBOL_CANON = {
    "_main": "main",
    "?GetProcessId@CProcess@@QAEKXZ": "GetProcessId",
    "_printf": "printf",
    "___local_stdio_printf_options": "__local_stdio_printf_options",
    "?assign@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAEAAV12@QBDI@Z": "string_assign",
    "??2@YAPAXI@Z": "operator_new",
    "@__security_check_cookie@4": "__security_check_cookie",
    "___security_check_cookie": "__security_check_cookie",
    "??3@YAXPAXI@Z": "operator_delete",
    "??4?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAEAAV01@QBD@Z": "string_operator_assign",
    "?assign@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAEAAV12@QBD@Z": "string_assign_char",
    "??_GCProcess@@QAEPAXI@Z": "CProcess_deleting_dtor",
    "??1CProcess@@QAE@XZ": "CProcess_dtor",
    "??0CProcess@@QAE@XZ": "CProcess_ctor",
}

# (display name, VA start, VA end, rebuilt symbol match) - user functions first.
ORIGINAL_FUNCS = [
    ("main", 0x401000, 0x4012B0, "_main"),
    ("CProcess::GetProcessId", 0x401300, 0x4013DC, "?GetProcessId@CProcess@@QAEKXZ"),
    ("printf (UCRT inline)", 0x4012D0, 0x401300, "_printf"),
    ("std::string::assign(char const*, size_t)", 0x401550, 0x40167F,
     "?assign@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAEAAV12@QBDI@Z"),
]

USER_FUNCS = ("main", "CProcess::GetProcessId")


def u32(d: bytes, o: int) -> int:
    return struct.unpack_from("<I", d, o)[0]


class PE:
    def __init__(self, path: Path):
        self.path = path
        self.data = path.read_bytes()
        lf = u32(self.data, 0x3C)
        opt = lf + 24
        self.image_base = u32(self.data, opt + 28)
        nsec = struct.unpack_from("<H", self.data, lf + 6)[0]
        osz = struct.unpack_from("<H", self.data, lf + 20)[0]
        sec = opt + osz
        self.sections = []
        for i in range(nsec):
            o = sec + i * 40
            name = self.data[o:o + 8].rstrip(b"\0").decode("ascii", "replace")
            vs = u32(self.data, o + 8)
            va = u32(self.data, o + 12)
            rs = u32(self.data, o + 16)
            rp = u32(self.data, o + 20)
            self.sections.append((name, va, vs, rp, rs))
        self.iat = {}
        self._parse_iat(opt)
        self._disasm = None

    def off(self, rva: int):
        for _n, va, vs, rp, rs in self.sections:
            if va <= rva < va + max(vs, rs):
                return rp + (rva - va)
        return None

    def _parse_iat(self, opt: int):
        import_rva = u32(self.data, opt + 96 + 1 * 8)
        if not import_rva:
            return
        o = self.off(import_rva)
        slot_rva = None
        while o is not None:
            ilt = u32(self.data, o)
            name_rva = u32(self.data, o + 12)
            first = u32(self.data, o + 16)
            if ilt == 0 and name_rva == 0 and first == 0:
                break
            if first:
                slot_rva = first
                thunk = self.off(ilt or first)
                idx = 0
                while thunk is not None:
                    val = u32(self.data, thunk)
                    if val == 0:
                        break
                    name = None
                    if not (val & 0x80000000):
                        no = self.off(val)
                        raw = self.data[no + 2:no + 2 + 80]
                        name = raw.split(b"\0", 1)[0].decode("ascii", "replace")
                    if name:
                        self.iat[self.image_base + slot_rva + idx * 4] = name
                    idx += 1
                    thunk += 4
            o += 20


def parse_map(path: Path):
    """Return {name: (va, size)} for all function symbols in a link map.

    MAP lines look like:  ``0001:00002900 _main 00403900 f main.obj``
    (section:offset, symbol, VA, flags, object). Section numbers are not assumed.
    """
    funcs = []
    for ln in path.read_text(errors="replace").splitlines():
        t = ln.split()
        if len(t) < 5 or not re.fullmatch(r"\d{4}:[0-9A-Fa-f]{8}", t[0]) or \
                not re.fullmatch(r"[0-9A-Fa-f]{8}", t[2]):
            continue
        if "f" not in t[3].lower():
            continue
        try:
            va = int(t[2], 16)
        except ValueError:
            continue
        funcs.append((va, t[1]))
    funcs.sort()
    out = {}
    for i, (va, name) in enumerate(funcs):
        nxt = funcs[i + 1][0] if i + 1 < len(funcs) else va + 0x40
        if name not in out and nxt > va:
            out[name] = (va, nxt - va)
    return out


INSTR_RE = re.compile(r"^\s*([0-9a-fA-F]+):\s+(?:[0-9a-fA-F]{2} )+\s*\t(.*)$")
HEX_RE = re.compile(r"0x([0-9a-fA-F]+)")


def disasm_all(pe: PE):
    """Disassemble the whole image once and cache the instruction list."""
    if pe._disasm is not None:
        return pe._disasm
    if not shutil.which(OBJDUMP) and not Path(OBJDUMP).exists():
        raise RuntimeError(
            "objdump not found on PATH. The structural diff needs MinGW binutils; "
            "install it (e.g. C:\\MinGW\\bin) or add objdump to PATH."
        )
    cmd = [OBJDUMP, "-d", "-M", "intel", str(pe.path)]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, errors="replace").stdout
    except OSError as exc:
        raise RuntimeError(f"failed to run objdump: {exc}") from exc
    instrs = []
    for ln in out.splitlines():
        m = INSTR_RE.match(ln)
        if not m:
            continue
        addr = int(m.group(1), 16)
        text = re.sub(r"\s+", " ", m.group(2).strip())
        text = text.split("#")[0].strip()
        parts = text.split(" ", 1)
        instrs.append((addr, parts[0], parts[1] if len(parts) > 1 else ""))
    pe._disasm = instrs
    return instrs


def disasm(pe: PE, start: int, end: int):
    return [i for i in disasm_all(pe) if start <= i[0] < end]


def normalize(instrs, start, end, iat, target_names):
    out = []
    for addr, mnem, ops in instrs:
        def sub_addr(m):
            va = int(m.group(1), 16)
            if va in iat:
                return "IMP:" + iat[va]
            if start <= va < end:
                return "SELF"
            if va in target_names:
                return "FN:" + target_names[va]
            if 0x400000 <= va < 0x500000:
                return "ADDR"
            return m.group(0)

        n = HEX_RE.sub(sub_addr, ops)
        n = re.sub(r"<[^>]*>", "", n)
        out.append(f"{mnem} {n}".strip())
    return out


def call_targets(instrs, start, end, iat, target_names):
    out = []
    for _addr, mnem, ops in instrs:
        if not mnem.startswith("call"):
            continue
        m = HEX_RE.search(ops)
        if not m:
            out.append("call:?")
            continue
        va = int(m.group(1), 16)
        if va in iat:
            out.append("call:IMP:" + iat[va])
        elif start <= va < end:
            out.append("call:SELF")
        elif va in target_names:
            out.append("call:FN:" + target_names[va])
        else:
            out.append("call:?")
    return sorted(out)


def lcs(a, b):
    if not a or not b:
        return 0
    prev = [0] * (len(b) + 1)
    for x in a:
        cur = [0]
        for j, y in enumerate(b):
            cur.append(prev[j] + 1 if x == y else max(prev[j + 1], cur[j]))
        prev = cur
    return prev[-1]


def score_function(orig: PE, new: PE, ostart: int, oend: int,
                   nstart: int, nsize: int, new_targets: dict):
    """Return a dict of similarity metrics for one function pair."""
    nend = nstart + nsize
    oi = disasm(orig, ostart, oend)
    ni = disasm(new, nstart, nend)
    on = normalize(oi, ostart, oend, orig.iat, ORIG_STARTS)
    nn = normalize(ni, nstart, nend, new.iat, new_targets)
    l = lcs(on, nn)
    lm = lcs([x.split(" ")[0] for x in on], [x.split(" ")[0] for x in nn])
    oc = call_targets(oi, ostart, oend, orig.iat, ORIG_STARTS)
    nc = call_targets(ni, nstart, nend, new.iat, new_targets)
    return {
        "orig_size": oend - ostart,
        "new_size": nsize,
        "orig_ins": len(on),
        "new_ins": len(nn),
        "lcs": l,
        "ins_sim": 200.0 * l / (len(on) + len(nn)) if on and nn else 0.0,
        "mnem_sim": 200.0 * lm / (len(on) + len(nn)) if on and nn else 0.0,
        "orig_branches": len({a for a, m, o in oi if m.startswith("j") or m == "call"}),
        "new_branches": len({a for a, m, o in ni if m.startswith("j") or m == "call"}),
        "call_sim": 100.0 * len(set(oc) & set(nc)) / max(len(set(oc) | set(nc)), 1),
    }


def new_target_map(funcs):
    targets = {}
    for sym, (va, _sz) in funcs.items():
        canon = SYMBOL_CANON.get(sym)
        if canon:
            targets[va] = canon
    return targets


def main():
    build_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "build"
    orig = PE(ROOT / "original" / "SKernelInjector.exe")
    new = PE(build_dir / "SKernelInjector.exe")
    funcs = parse_map(build_dir / "SKernelInjector.map")
    new_targets = new_target_map(funcs)

    print(f"original: {orig.path}  ({len(orig.data)} bytes)")
    print(f"rebuilt : {new.path}  ({len(new.data)} bytes)")
    print(f"build funcs in .text: {len(funcs)}")
    print()
    header = (f"{'function':42s} {'orig':>6s} {'new':>6s} {'ins':>4s}/{'':4s} "
              f"{'LCS%':>6s} {'mnem%':>6s} {'blocks':>6s} {'calls%':>7s}")
    print(header)
    print("-" * len(header))
    total_weight = 0.0
    total_score = 0.0
    missing_user = []
    for disp, ostart, oend, symbol in ORIGINAL_FUNCS:
        if symbol not in funcs:
            if disp in USER_FUNCS:
                missing_user.append(disp)
            continue
        nstart, nsize = funcs[symbol]
        m = score_function(orig, new, ostart, oend, nstart, nsize, new_targets)
        print(f"{disp:42s} 0x{m['orig_size']:04X} 0x{m['new_size']:04X} "
              f"{m['orig_ins']:4d}/{m['new_ins']:4d} {m['ins_sim']:6.1f} "
              f"{m['mnem_sim']:6.1f} {m['orig_branches']:3d}/{m['new_branches']:3d} "
              f"{m['call_sim']:7.1f}")
        if disp in USER_FUNCS:
            weight = oend - ostart
            total_weight += weight
            total_score += m["ins_sim"] * weight
    print()
    if missing_user:
        print(f"MISSING user functions in rebuilt map: {missing_user}")
    if total_weight:
        print(f"weighted user-code similarity: {total_score / total_weight:.1f}%")
    else:
        print("weighted user-code similarity: n/a (no user functions found)")


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(2)
