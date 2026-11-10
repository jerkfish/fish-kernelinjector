# SKernelInjector — Source Recovery State

**Target:** `SKernelInjector.exe` (SHA-256 `085f66104949340757cdb7d79b0034677ba622f08997c0c4ba96edc3550272cf`,
MD5 `fe433288058f777820e5bc5d7aa1e9a0`, 19,824 bytes)
**Original (read-only copy):** `original/SKernelInjector.exe`
**IDA database:** open in IDA Pro via MCP; unpacked `.id0/.id1/.id2/.nam/.til` next to
the original are locked by IDA while it is running. A copy of `.id2/.til` was taken before
edits; `.id0/.id1/.nam` could not be copied while IDA holds them. The original EXE is the
immutable source of truth, and no destructive database operations were performed.
**Git identity:** `konata1998 <jerkfish123@gmail.com>`; no co-author/generated-with
trailers (user instruction, 2026-11-10).

---

## Phase status

| Phase | Status |
|---|---|
| 0 — Recon | **COMPLETE** |
| 1 — API/ABI surface | **COMPLETE (N/A)** — target is an EXE, zero exports; no public header |
| 2 — Types | **COMPLETE** — `CProcess` (0x1C), MSVC `std::string` layout verified |
| 3 — Function-by-function | **COMPLETE — 2/2 user functions recovered, compiled, behaviourally verified** |
| 4 — Global integration | **COMPLETE** — build, full verification |
| Final loop exit | **MET** — builds clean, exports match (none), behaviour passes; two structural exceptions documented (toolset deltas) |

---

## Phase 0 — RECON (summary; full detail in NOTES/evidence.md)

| Property | Value |
|---|---|
| Format | PE32 x86 (i386), **EXE (not DLL)**, console subsystem (3) |
| Linker | 14.30; timestamp 0x625F5BBF = 2022-04-20 07:42:55 UTC |
| Sections | `.text .rdata .data .rsrc .reloc` (5 — LTCG-merged) |
| Exports / TLS | none / none |
| Manifest | `requireAdministrator` (RT_MANIFEST, 392 bytes, lang 1033) |
| Debug | `E:\l4d2\Win32\Release\SKernelInjector.pdb`, GUID `db6f12fb…`, age 1 |
| DllCharacteristics | 0x8140 (DYNAMICBASE, NX_COMPAT, TERMINAL_SERVER_AWARE) |
| Load config | cookie 0x405004; SAFESEH 2 entries; GuardCFCheckFunctionPointer set; **GuardFlags 0x100, CFG table empty** |
| Imports | KERNEL32 (25), MSVCP140 (`_Xlength_error`), VCRUNTIME140 (10), UCRT api-sets |
| Runtime | **dynamic CRT `/MD`**; Rich header MSVC 14.30 (VS2022 17.0.x) |
| Codegen | `/O2`-class, `/GS` cookies, C++ EH (`__CxxFrameHandler3`), SAFESEH, LTCG, no `/guard:cf` at link |

**Library code excluded from recovery:** everything except `0x401000 main` and
`0x401300 GetProcessId` is MSVC CRT/STL (UCRT inline `printf`, `std::string::assign`,
STL exception machinery, `operator new/delete`, CRT startup, GS/SEH support). Replaced by
real headers/library calls and the same compiler.

---

## Phase 1 — API/ABI

No exports, no DLL entry point, no public ABI. `include/` therefore contains only a note.
The observable interface is process stdout/stderr, the exit code (the `_getwch` key code),
and the Win32 side effects (process enumeration / remote-thread injection).

## Phase 2 — Types

```cpp
struct CProcess {        // sizeof == 0x1C (28), proved by operator new(0x1C)
    HANDLE hProcess;     // +0x00 (OpenProcess result)
    std::string szName;  // +0x04; MSVC x86 std::string: buffer/ptr +0, size +0x10, cap +0x14
    DWORD GetProcessId();// __thiscall (ecx = this)
};
```

Ownership: `std::unique_ptr<CProcess>` (evidence: EH cleanup funclet deletes the object;
EH state stays 0 for the entire function, i.e. cleanup active on every later exception,
which is RAII semantics, not new-expression construction cleanup).

## Phase 3 — Functions

| Function | Address | Size (orig → rebuild) | Instruction LCS | Call targets | Status |
|---|---|---|---|---|---|
| `main` | 0x401000 | 0x2B0 → **0x2B0** | 88.2% | **100%** | DONE (compiled + behaviour) |
| `CProcess::GetProcessId` | 0x401300 | 0x0DC → 0x0E0 | **95.2%** | **100%** | DONE (compiled + behaviour) |
| UCRT inline `printf` | 0x4012D0 | 0x030 → 0x030 | 71.8% | 50% | LIBRARY (from `<cstdio>`) |
| `std::string::assign(ptr,size)` | 0x401550 | 0x12F → 0x130 | 26.3%* | 33.3%* | LIBRARY (LTCG-specialised) |

\* Library-only delta: the rebuild calls `assign` with a compile-time constant, so LTCG
specialises it (no general growth path / `memcpy` import). Behaviour identical; not counted
toward the user-function criterion.

Structural deltas in user code are scheduling/encoding only:
- `main`: value-init zeroing order; deferred `esp` cleanups around `printf`; one hoisted
  `GetModuleHandleA` argument push. Branch sites 42 vs 43, same blocks/calls/constants.
- `GetProcessId`: `cmp cap,0xf/jbe` vs `cmp cap,0x10/jb` (equivalent) + 4 bytes padding.

## Phase 4 — Build & verification

Build: `tools/build.bat` → `build/SKernelInjector.exe` (0 errors).
Toolset: MSVC **14.38.33130** + SDK 10.0.22621 (original 14.30 unavailable).
Flags: `cl /O2 /Ob1 /GL /MD /GS /EHsc /DNDEBUG /DWIN32 /D_WINDOWS`;
link `/LTCG /SUBSYSTEM:CONSOLE /DEBUG /MANIFEST:EMBED
/MANIFESTUAC:"level='requireAdministrator' uiAccess='false'"`.
`/Ob1` compensates for 14.38's more aggressive LTCG inliner (see README).

### Verification metrics (last run)

| Metric | Result |
|---|---|
| Build | **PASS** |
| Exports match | **PASS** (none / none) |
| PE surface (machine, subsystem, sections, DllCharacteristics, GuardFlags) | **PASS** |
| Manifest | **PASS** (byte-identical, 392 bytes) |
| Win32/MSVCP imports | **PASS** (all functional imports present) |
| Behavioural tests | **PASS 2/2** (stdout + exit code identical; absent/present game) |
| User functions structurally near-identical | 1/2 ≥95% (GetProcessId 95.2%); main 88.2% with documented toolset reason; **weighted 89.9%** |
| BLOCKED | none |

## Open questions

1. **MSVC 14.30 toolset not installed.** If the user wants byte-exact `.text`, install
   VS2022 17.0's toolset and rebuild with the recorded flags. Current source is shaped for
   that compiler (out-of-line `assign`, value-init zeroing pattern).
2. **Original PDB missing** (`E:\l4d2\Win32\Release\SKernelInjector.pdb`). If found, it
   would confirm identifiers/lines. Not blocking.
3. **IDA database backup**: `.id0/.id1/.nam` are file-locked by the running IDA session;
   only `.id2/.til` were copied. No bulk rename/type surgery was performed; the DB can be
   regenerated from the original EXE.

## Next (only if requested)

- Install/point at MSVC 14.30 and rerun `tools/compare.py` for a byte-level pass.
- If the PDB appears, reconcile symbol names (no behavioural change expected).
- Optional: run `tools/verify.py` + `tests/behavior_test.py` in CI.
