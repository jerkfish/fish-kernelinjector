#!/usr/bin/env python3
"""Dump PE header facts for SKernelInjector.exe (Phase 0 recon).

Pure-stdlib PE parser: DOS/NT headers, sections, data directories, imports,
exports, TLS callbacks, resources, debug directory, Rich header.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path


def u16(b: bytes, o: int) -> int:
    return struct.unpack_from("<H", b, o)[0]


def u32(b: bytes, o: int) -> int:
    return struct.unpack_from("<I", b, o)[0]


def cstr(b: bytes, o: int) -> str:
    end = b.index(b"\0", o)
    return b[o:end].decode("ascii", "replace")


def rich_header(data: bytes, lfanew: int) -> list[tuple[str, int, int]]:
    """Decode the Rich header: XOR key from 'Rich', then entries."""
    rich_off = data.rfind(b"Rich", 0, lfanew)
    if rich_off < 0:
        return []
    key = u32(data, rich_off + 4)
    # DanS marks the start, XOR-encrypted with key.
    dans_val = 0x536E6144 ^ key
    start = -1
    for o in range(0x40, rich_off - 8, 4):
        if u32(data, o) == dans_val:
            start = o
            break
    if start < 0:
        return []
    entries = []
    pos = start + 16  # DanS + 3 padding dwords
    product_names = {
        0: "Unknown", 1: "Import0", 2: "Linker510", 3: "Cvtomf510",
        4: "Linker600", 5: "Cvtomf600", 6: "Cvtres500",
        7: "Utc11_Basic", 8: "Utc11_C", 9: "Utc12_Basic", 10: "Utc12_C",
        11: "Utc12_CPP", 12: "AliasObj60", 13: "VisualBasic60",
        14: "Masm613", 15: "Masm710", 16: "Linker511", 17: "Cvtomf511",
        18: "Masm614", 19: "Linker512", 20: "Cvtomf512",
        21: "Utc12_C_Std", 22: "Utc12_CPP_Std", 23: "Utc12_C_Book",
        24: "Utc12_CPP_Book", 25: "Implib700", 26: "Cvtomf700",
        27: "Utc13_Basic", 28: "Utc13_C", 29: "Utc13_CPP",
        30: "Linker610", 31: "Cvtomf610", 32: "Linker601",
        33: "Cvtomf601", 34: "Utc12_1_Basic", 35: "Utc12_1_C",
        36: "Utc12_1_CPP", 37: "Linker620", 38: "Cvtomf620",
        39: "AliasObj70", 40: "Linker621", 41: "Cvtomf621",
        42: "Masm615", 43: "Utc13_LTCG_C", 44: "Utc13_LTCG_CPP",
        45: "Masm620", 46: "ILAsm100", 47: "Utc12_2_Basic",
        48: "Utc12_2_C", 49: "Utc12_2_CPP", 50: "Utc12_2_C_Std",
        51: "Utc12_2_CPP_Std", 52: "Utc12_2_C_Book",
        53: "Utc12_2_CPP_Book", 54: "Implib622", 55: "Cvtomf622",
        56: "Cvtres501", 57: "Utc13_C_Std", 58: "Utc13_CPP_Std",
        59: "Cvtpgd1300", 60: "Linker622", 61: "Linker700",
        62: "Export622", 63: "Export700", 64: "Masm700",
        65: "Utc13_POGO_I_C", 66: "Utc13_POGO_I_CPP",
        67: "Utc13_POGO_O_C", 68: "Utc13_POGO_O_CPP",
        69: "Cvtres700", 70: "Cvtres710p", 71: "Linker710p",
        72: "Cvtomf710p", 73: "Export710p", 74: "Implib710p",
        75: "Masm710p", 76: "Utc1310p_C", 77: "Utc1310p_CPP",
        78: "Utc1310p_C_Std", 79: "Utc1310p_CPP_Std",
        80: "Utc1310p_LTCG_C", 81: "Utc1310p_LTCG_CPP",
        82: "Utc1310p_POGO_I_C", 83: "Utc1310p_POGO_I_CPP",
        84: "Utc1310p_POGO_O_C", 85: "Utc1310p_POGO_O_CPP",
        86: "Linker624", 87: "Cvtomf624", 88: "Export624",
        89: "Implib624", 90: "Linker710", 91: "Cvtomf710",
        92: "Export710", 93: "Implib710", 94: "Cvtres710",
        95: "Utc1310_C", 96: "Utc1310_CPP", 97: "Utc1310_C_Std",
        98: "Utc1310_CPP_Std", 99: "Utc1310_LTCG_C",
        100: "Utc1310_LTCG_CPP", 101: "Utc1310_POGO_I_C",
        102: "Utc1310_POGO_I_CPP", 103: "Utc1310_POGO_O_C",
        104: "Utc1310_POGO_O_CPP", 105: "AliasObj710",
        106: "AliasObj710p", 107: "Cvtpgd1310", 108: "Cvtpgd1310p",
        109: "Utc1400_C", 110: "Utc1400_CPP", 111: "Utc1400_C_Std",
        112: "Utc1400_CPP_Std", 113: "Utc1400_LTCG_C",
        114: "Utc1400_LTCG_CPP", 115: "Utc1400_POGO_I_C",
        116: "Utc1400_POGO_I_CPP", 117: "Utc1400_POGO_O_C",
        118: "Utc1400_POGO_O_CPP", 119: "Cvtpgd1400",
        120: "Linker800", 121: "Cvtomf800", 122: "Export800",
        123: "Implib800", 124: "Cvtres800", 125: "Masm800",
        126: "AliasObj800", 127: "PhoenixPrerelease",
        128: "Utc1400_CVTCIL_C", 129: "Utc1400_CVTCIL_CPP",
        130: "Utc1400_LTCG_MSIL", 131: "Utc1500_C", 132: "Utc1500_CPP",
        133: "Utc1500_C_Std", 134: "Utc1500_CPP_Std",
        135: "Utc1500_CVTCIL_C", 136: "Utc1500_CVTCIL_CPP",
        137: "Utc1500_LTCG_C", 138: "Utc1500_LTCG_CPP",
        139: "Utc1500_LTCG_MSIL", 140: "Utc1500_POGO_I_C",
        141: "Utc1500_POGO_I_CPP", 142: "Utc1500_POGO_O_C",
        143: "Utc1500_POGO_O_CPP", 144: "Cvtpgd1500",
        145: "Linker900", 146: "Export900", 147: "Implib900",
        148: "Cvtres900", 149: "Masm900", 150: "AliasObj900",
        151: "Resource900", 152: "AliasObj1000", 153: "Cvtpgd1600",
        154: "Cvtres1000", 155: "Export1000", 156: "Implib1000",
        157: "Linker1000", 158: "Masm1000", 159: "Utc1600_C",
        160: "Utc1600_CPP", 161: "Utc1600_CVTCIL_C",
        162: "Utc1600_CVTCIL_CPP", 163: "Utc1600_LTCG_C",
        164: "Utc1600_LTCG_CPP", 165: "Utc1600_LTCG_MSIL",
        166: "Utc1600_POGO_I_C", 167: "Utc1600_POGO_I_CPP",
        168: "Utc1600_POGO_O_C", 169: "Utc1600_POGO_O_CPP",
        170: "Utc1700_C", 171: "Utc1700_CPP", 172: "Utc1700_CVTCIL_C",
        173: "Utc1700_CVTCIL_CPP", 174: "Utc1700_LTCG_C",
        175: "Utc1700_LTCG_CPP", 176: "Utc1700_LTCG_MSIL",
        177: "Utc1700_POGO_I_C", 178: "Utc1700_POGO_I_CPP",
        179: "Utc1700_POGO_O_C", 180: "Utc1700_POGO_O_CPP",
        181: "AliasObj1700", 182: "Cvtres1700", 183: "Export1700",
        184: "Implib1700", 185: "Linker1700", 186: "Masm1700",
        187: "Utc1800_C", 188: "Utc1800_CPP", 189: "Utc1800_CVTCIL_C",
        190: "Utc1800_CVTCIL_CPP", 191: "Utc1800_LTCG_C",
        192: "Utc1800_LTCG_CPP", 193: "Utc1800_LTCG_MSIL",
        194: "Utc1800_POGO_I_C", 195: "Utc1800_POGO_I_CPP",
        196: "Utc1800_POGO_O_C", 197: "Utc1800_POGO_O_CPP",
        198: "AliasObj1800", 199: "Cvtres1800", 200: "Export1800",
        201: "Implib1800", 202: "Linker1800", 203: "Masm1800",
        204: "Utc1900_C", 205: "Utc1900_CPP", 206: "Utc1900_CVTCIL_C",
        207: "Utc1900_CVTCIL_CPP", 208: "Utc1900_LTCG_C",
        209: "Utc1900_LTCG_CPP", 210: "Utc1900_LTCG_MSIL",
        211: "Utc1900_POGO_I_C", 212: "Utc1900_POGO_I_CPP",
        213: "Utc1900_POGO_O_C", 214: "Utc1900_POGO_O_CPP",
        215: "AliasObj1900", 216: "Cvtres1900", 217: "Export1900",
        218: "Implib1900", 219: "Linker1900", 220: "Masm1900",
    }
    while pos + 8 <= rich_off:
        comp_id = u32(data, pos) ^ key
        count = u32(data, pos + 4) ^ key
        if comp_id == 0 and count == 0:
            break
        prod = (comp_id >> 16) & 0xFFFF
        build = comp_id & 0xFFFF
        name = product_names.get(prod, f"Prod{prod}")
        entries.append((name, build, count))
        pos += 8
    return entries


def main(path: Path) -> None:
    data = path.read_bytes()
    print(f"file            : {path}")
    print(f"size            : {len(data)} (0x{len(data):X})")
    if data[:2] != b"MZ":
        print("not a PE")
        return
    lfanew = u32(data, 0x3C)
    print(f"e_lfanew        : 0x{lfanew:X}")
    assert data[lfanew:lfanew + 4] == b"PE\0\0"
    coff = lfanew + 4
    machine = u16(data, coff)
    nsec = u16(data, coff + 2)
    timestamp = u32(data, coff + 4)
    opt_size = u16(data, coff + 16)
    characteristics = u16(data, coff + 18)
    machines = {0x14C: "i386", 0x8664: "x64", 0x1C0: "ARM", 0xAA64: "ARM64"}
    print(f"machine         : 0x{machine:04X} ({machines.get(machine, '?')})")
    print(f"sections        : {nsec}")
    print(f"timestamp       : 0x{timestamp:08X} ({timestamp} unix)")
    print(f"characteristics : 0x{characteristics:04X}")
    opt = coff + 20
    magic = u16(data, opt)
    pe32plus = magic == 0x20B
    print(f"optional magic  : 0x{magic:04X} ({'PE32+' if pe32plus else 'PE32'})")
    if pe32plus:
        print("PE32+ (x64) images are not supported by this PE32-only recon dump.")
        return
    link_major = data[opt + 2]
    link_minor = data[opt + 3]
    print(f"linker version  : {link_major}.{link_minor}")
    print(f"entry point RVA : 0x{u32(data, opt + 16):X}")
    print(f"image base      : 0x{u32(data, opt + 28):X}")
    print(f"section align   : 0x{u32(data, opt + 32):X}")
    print(f"file align      : 0x{u32(data, opt + 36):X}")
    print(f"OS version      : {u16(data, opt + 40)}.{u16(data, opt + 42)}")
    print(f"subsystem ver   : {u16(data, opt + 48)}.{u16(data, opt + 50)}")
    print(f"image version   : {u16(data, opt + 44)}.{u16(data, opt + 46)}")
    print(f"subsystem       : {u16(data, opt + 68)}")
    print(f"DllCharacteristics: 0x{u16(data, opt + 70):04X}")
    print(f"SizeOfStackReserve: 0x{u32(data, opt + 72):X}")
    print(f"SizeOfStackCommit : 0x{u32(data, opt + 76):X}")
    print(f"SizeOfHeapReserve : 0x{u32(data, opt + 80):X}")
    print(f"SizeOfHeapCommit  : 0x{u32(data, opt + 84):X}")
    print(f"NumberOfRvaAndSizes: {u32(data, opt + 92)}")

    dir_names = ["export", "import", "resource", "exception", "security",
                 "basereloc", "debug", "architecture", "globalptr", "tls",
                 "loadconfig", "boundimport", "iat", "delayimport",
                 "clr", "reserved"]
    dd = opt + 96
    dirs = []
    for i, name in enumerate(dir_names):
        rva = u32(data, dd + i * 8)
        size = u32(data, dd + i * 8 + 4)
        dirs.append((name, rva, size))
        if rva or size:
            print(f"dir[{i:02d}] {name:11s}: RVA 0x{rva:X} size 0x{size:X}")

    sec_off = opt + opt_size
    sections = []
    print("\nSections:")
    for i in range(nsec):
        o = sec_off + i * 40
        name = data[o:o + 8].rstrip(b"\0").decode("ascii", "replace")
        vsize = u32(data, o + 8)
        vaddr = u32(data, o + 12)
        rawsize = u32(data, o + 16)
        rawptr = u32(data, o + 20)
        chars = u32(data, o + 36)
        sections.append((name, vaddr, vsize, rawptr, rawsize))
        print(f"  {name:8s} VA 0x{vaddr:06X} vsize 0x{vsize:06X} "
              f"raw 0x{rawptr:06X} rawsize 0x{rawsize:06X} chars 0x{chars:08X}")

    def rva_to_off(rva: int) -> int | None:
        for _n, va, vs, rp, rs in sections:
            if va <= rva < va + max(vs, rs):
                return rp + (rva - va)
        return None

    # Imports
    imp = next((d for d in dirs if d[0] == "import"), None)
    print("\nImports:")
    if imp and imp[1]:
        o = rva_to_off(imp[1])
        while True:
            ilt = u32(data, o)
            name_rva = u32(data, o + 12)
            first = u32(data, o + 16)
            if ilt == 0 and name_rva == 0 and first == 0:
                break
            dll = cstr(data, rva_to_off(name_rva))
            thunk = ilt or first
            funcs = []
            to = rva_to_off(thunk)
            while True:
                val = u32(data, to)
                if val == 0:
                    break
                if val & 0x80000000:
                    funcs.append(f"#{val & 0xFFFF}")
                else:
                    funcs.append(cstr(data, rva_to_off(val) + 2))
                to += 4
            print(f"  {dll}: {', '.join(funcs)}")
            o += 20
    else:
        print("  (none)")

    # Exports
    exp = next((d for d in dirs if d[0] == "export"), None)
    print("\nExports:")
    if exp and exp[1]:
        o = rva_to_off(exp[1])
        name_rva = u32(data, o + 12)
        nfuncs = u32(data, o + 20)
        nnames = u32(data, o + 24)
        funcs_rva = u32(data, o + 28)
        names_rva = u32(data, o + 32)
        ords_rva = u32(data, o + 36)
        dll = cstr(data, rva_to_off(name_rva))
        print(f"  DLL name: {dll}, functions: {nfuncs}, names: {nnames}")
        no = rva_to_off(names_rva)
        oo = rva_to_off(ords_rva)
        fo = rva_to_off(funcs_rva)
        for i in range(nnames):
            nm = cstr(data, rva_to_off(u32(data, no + i * 4)))
            ordinal = u16(data, oo + i * 2)
            frva = u32(data, fo + ordinal * 4)
            print(f"  {nm} @ ordinal {ordinal} RVA 0x{frva:X}")
    else:
        print("  (none)")

    # TLS
    tls = next((d for d in dirs if d[0] == "tls"), None)
    print("\nTLS:")
    if tls and tls[1]:
        o = rva_to_off(tls[1])
        start_va, end_va, index_va, cb_va = struct.unpack_from("<IIII", data, o)
        callbacks_va, zerofill, chars = struct.unpack_from("<III", data, o + 12)
        print(f"  StartAddressOfRawData 0x{start_va:X}")
        print(f"  EndAddressOfRawData   0x{end_va:X}")
        print(f"  AddressOfIndex        0x{index_va:X}")
        print(f"  AddressOfCallBacks    0x{callbacks_va:X}")
        print(f"  SizeOfZeroFill        0x{zerofill:X}")
        print(f"  Characteristics       0x{chars:X}")
        if callbacks_va:
            # VA -> RVA via image base
            image_base = u32(data, opt + 28)
            rva = callbacks_va - image_base
            co = rva_to_off(rva)
            if co is not None:
                while True:
                    cb = u32(data, co)
                    if cb == 0:
                        break
                    print(f"  callback VA 0x{cb:X} (RVA 0x{cb - image_base:X})")
                    co += 4
    else:
        print("  (none)")

    # Resources
    res = next((d for d in dirs if d[0] == "resource"), None)
    print("\nResources:")
    if res and res[1]:
        base = rva_to_off(res[1])
        num_named = u16(data, base + 12)
        num_id = u16(data, base + 14)

        def walk(off: int, depth: int, prefix: str) -> None:
            n_named = u16(data, off + 12)
            n_id = u16(data, off + 14)
            for i in range(n_named + n_id):
                e = off + 16 + i * 8
                name_field = u32(data, e)
                target = u32(data, e + 4)
                if name_field & 0x80000000:
                    noff = base + (name_field & 0x7FFFFFFF)
                    length = u16(data, noff)
                    label = data[noff + 2: noff + 2 + length * 2].decode("utf-16le", "replace")
                else:
                    label = str(name_field)
                if target & 0x80000000:
                    walk(base + (target & 0x7FFFFFFF), depth + 1, prefix + "/" + label)
                else:
                    data_off = base + target
                    data_rva = u32(data, data_off)
                    data_size = u32(data, data_off + 4)
                    print(f"  {prefix}/{label}: RVA 0x{data_rva:X} size 0x{data_size:X}")

        walk(base, 0, "")
    else:
        print("  (none)")

    # Debug directory
    dbg = next((d for d in dirs if d[0] == "debug"), None)
    print("\nDebug:")
    if dbg and dbg[1]:
        o = rva_to_off(dbg[1])
        count = dbg[2] // 28
        for i in range(count):
            e = o + i * 28
            size = u32(data, e + 16)
            ptr = u32(data, e + 24)
            if ptr and size:
                blob = data[ptr:ptr + size]
                if blob[:4] == b"RSDS":
                    guid = blob[4:20]
                    age = u32(blob, 20)
                    pdb = cstr(blob, 24)
                    print(f"  CodeView RSDS: PDB={pdb!r} age={age} guid={guid.hex()}")
    else:
        print("  (none)")

    # Rich header
    print("\nRich header:")
    entries = rich_header(data, lfanew)
    if not entries:
        print("  (none)")
    for name, build, count in entries:
        print(f"  {name:24s} build {build:5d} count {count}")

    # Load config (security cookie, SEH)
    lc = next((d for d in dirs if d[0] == "loadconfig"), None)
    print("\nLoad config:")
    if lc and lc[1]:
        o = rva_to_off(lc[1])
        struct_size = u32(data, o)          # IMAGE_LOAD_CONFIG_DIRECTORY32.Size
        dir_size = lc[2]                    # data-directory entry size
        cookie_va = u32(data, o + 0x3C) if struct_size >= 0x40 else 0
        seh_va = u32(data, o + 0x40) if struct_size >= 0x44 else 0
        seh_count = u32(data, o + 0x44) if struct_size >= 0x48 else 0
        guard_flags = u32(data, o + 0x58) if struct_size >= 0x5C else None
        print(f"  Size 0x{struct_size:X} (data directory entry 0x{dir_size:X})")
        print(f"  SecurityCookie VA 0x{cookie_va:X}")
        print(f"  SEHandlerTable VA 0x{seh_va:X} count {seh_count}")
        if guard_flags is not None:
            print(f"  GuardFlags 0x{guard_flags:X}")
    else:
        print("  (none)")


ROOT = Path(__file__).resolve().parent.parent

if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "original" / "SKernelInjector.exe"
    main(target)
