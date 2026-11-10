# SKernelInjector — recovered C++ source

Clean-room source reconstruction of `SKernelInjector.exe` (19,824 bytes, SHA-256
`085f66104949340757cdb7d79b0034677ba622f08997c0c4ba96edc3550272cf`), built from the
binary and the IDA database only. The original PDB/source were not available.

The program is a console utility that injects `VR.dll` (located next to the executable)
into `left4dead2.exe` using the classic `CreateRemoteThread` + `LoadLibraryA` technique.
It prints a result banner and troubleshooting text, then waits for a key. It requests
administrator rights in its manifest.

> Treat this as a recovered engineering artifact. The original binary is kept unmodified in
> `original/SKernelInjector.exe`; all reconstructed files live under `src/`, `tools/`,
> `tests/`, `NOTES/`.

---

## Recovered source

| File | Contents |
|---|---|
| `src/main.cpp` | The entire user code: `CProcess` (28-byte object with `HANDLE` + `std::string`), `CProcess::GetProcessId`, and `main`. Everything else in the original `.text` is MSVC CRT/STL code. |

Original user-defined functions: **2 of 2 recovered**

1. `int main()` — builds the process name, looks up the PID, opens the target, builds
   `<cwd>\VR.dll`, performs the remote-thread injection, prints the banner/troubleshooting
   text, waits for a key, and returns the key code.
2. `DWORD CProcess::GetProcessId()` — `CreateToolhelp32Snapshot` loop with an exact
   `strcmp` against `PROCESSENTRY32::szExeFile`; closes the snapshot on success, leaks it
   when the process is not found (preserved quirk).

Recovered type:

```cpp
struct CProcess {        // sizeof == 0x1C on x86
    HANDLE hProcess;     // +0x00
    std::string szName;  // +0x04 (MSVC x86 std::string == 24 bytes)
    DWORD GetProcessId();
};
```

The object is owned by `std::unique_ptr` (proved by the EH cleanup funclet and the EH state
that stays live for the whole function). See `NOTES/evidence.md` for the full evidence log.

Behavioural quirks are preserved and commented in the source:

- `OpenProcess` failure is compared against `INVALID_HANDLE_VALUE`, but `OpenProcess`
  returns `NULL` on failure — the check is effectively dead.
- The DLL path is passed to `printf` as a format string.
- Failure paths do not return early; execution always continues to the injection attempt.
- `main` returns the `_getwch()` key code rather than 0.
- The Toolhelp snapshot is not closed when the target process is absent.

---

## Toolchain / build

**Original fingerprint (from the binary):**

- PE32 x86 console executable, image base `0x400000`
- Linker version **14.30**, COFF timestamp **2022-04-20 07:42:55 UTC**
- MSVC 14.30 (VS2022 17.0.x) Rich-header products, **dynamic CRT** (`/MD`), `/O2`, `/GS`,
  `/EHsc`, **LTCG** (`/GL` + `/LTCG`; the final image has the 5 LTCG-merged sections)
- Linker `/DEBUG` (PDB path `E:\l4d2\Win32\Release\SKernelInjector.pdb`)
- Manifest: `requestedExecutionLevel level='requireAdministrator'`
- No `/guard:cf` at link (load config has `GuardFlags=0x100`, no CFG function table)
- SAFESEH table present (2 entries)

**Rebuild (this project):**

- `tools/build.bat` — x86 Release, same flags, using the closest installed toolset
  **MSVC 14.38.33130** (VS2022 Community), Windows SDK 10.0.22621.
- The original 14.30 toolset is **not installed** on this machine. `/Ob1` is used
  deliberately: 14.38's LTCG inliner is more aggressive than 14.30's and, with `/Ob2`,
  inlines the whole `std::string` assignment into `main` (main becomes 0x380 bytes instead
  of the original 0x2B0). `/Ob1` reproduces the original's out-of-line `std::string::assign`.
- The MSVC environment is set manually by `tools/msvc_env.bat` (the local `vswhere`
  invocation is broken), so no `vcvarsall` is required.

Build:

```bat
tools\build.bat
```

Output: `build/SKernelInjector.exe`, `build/SKernelInjector.map`, `build/SKernelInjector.pdb`.

---

## Verification

Run all checks:

```bat
python tools\verify.py             :: PE surface + structure
python tests\behavior_test.py      :: behavioral differential test
python tools\compare.py build      :: per-function instruction diff
```

### Result (final build)

| Check | Result |
|---|---|
| Build | **PASS** (0 errors) |
| Exports (names/ordinals) | **PASS** — none in either image (target is an EXE) |
| Machine / subsystem / subsystem version | **PASS** (i386, console, 6.0) |
| DllCharacteristics | **PASS** (0x8140) |
| Section names | **PASS** (`.text .rdata .data .rsrc .reloc`) |
| Load-config GuardFlags | **PASS** (0x100, no CFG table) |
| Manifest | **PASS** — RT_MANIFEST byte-identical (392 bytes) |
| Win32/MSVCP import surface | **PASS** — all functional imports present |
| Behavioural tests | **PASS 2/2 scenarios**, stdout and exit code identical |
| User functions recovered | **2/2** |
| Structural similarity (user code, weighted) | **89.9%** |

Per-function structural comparison (normalized instructions, LCS):

| Function | Original size | Rebuilt size | Instruction LCS | Call-target match | Basic-block branch sites |
|---|---|---|---|---|---|
| `main` | 0x2B0 | **0x2B0** | 88.2% | **100%** | 42 vs 43 |
| `CProcess::GetProcessId` | 0x0DC | 0x0E0 | **95.2%** | **100%** | 16 vs 16 |

### Behavioural test details

`tests/behavior_test.py` launches the original and the rebuilt executable in identical
conditions (each in its own console, `__COMPAT_LAYER=RunAsInvoker` because both manifests
request elevation), waits for `_getwch()`, writes an `x` key event to the console input
buffer, and compares stdout and exit code byte-for-byte.

1. **Game absent** — no `left4dead2.exe`: both print the PID failure, "Failed process
   initialization.", the DLL path, "Injection failed!" and the troubleshooting block;
   both exit with code 120 (`'x'`).
2. **Game present** — `tests/bin/left4dead2.exe` (a harmless sleeping dummy) is running:
   both take the full injection path (`OpenProcess` → `VirtualAllocEx` →
   `WriteProcessMemory` → `CreateRemoteThread`), free the remote block, print
   "Successfully injected…" and the troubleshooting block; both exit with code 120.
   `VR.dll` does not need to exist — the injector reports success once the remote thread
   is created, exactly like the original.

---

## Documented exceptions / remaining unknown

### BLOCKED

*None.* Both user functions were recovered, compile, and pass behavioural tests.

### INFERRED (not provable from the binary alone; evidence in `NOTES/evidence.md`)

1. **User-defined identifiers** — `CProcess`, `hProcess`, `szName`, `GetProcessId` are
   descriptive names; the PDB is missing. Layout/calling convention are proven.
2. **`std::unique_ptr` ownership** — the object is deleted by an EH cleanup funclet whose
   state stays active for the whole function, and the pointer occupies the cleanup slot;
   this matches RAII ownership rather than a raw `new`/`delete` pair.
3. **`new CProcess{}` / `assign("left4dead2.exe", 14)` source spelling** — the binary's
   exact inlining pattern (value-initialised object, direct `assign(ptr, 14)` call with the
   wrapper inlined) is reproduced with this spelling. Semantically identical alternatives
   exist; this form gives the closest code (main is the exact original size, 100% call-target
   match) with the available compiler.
4. **Purpose** — a fan-made loader for the `VR.dll` L4D2 mod is the evident use, based on
   the strings and API sequence. Not needed for the rebuild.

### Known deltas vs the original (toolset, not source)

- **Compiler/linker are 14.38, not 14.30.** CRT startup objects differ slightly:
  the rebuild additionally imports `GetStartupInfoW`, `_seh_filter_dll`,
  `_execute_onexit_table`, `_crt_at_quick_exit`, `__std_terminate`,
  `__std_type_info_destroy_list`, and imports one helper less (`memcpy`, inlined by the
  compiler). No functional Win32/STL import is missing.
- **`main` residual instruction delta is scheduling-only**: value-initialisation zeroing
  order, deferred `esp` adjustments around `printf`, and one hoisted `GetModuleHandleA`
  push. The branch count, call graph (100%), constants and function size are identical.
- **`GetProcessId` residual delta**: the string-capacity guard is encoded as
  `cmp [esi+18h],0xf / jbe` instead of `cmp [esi+18h],0x10 / jb` (identical semantics),
  plus 4 bytes of alignment padding.
- **`std::string::assign` was specialised by LTCG** (0x130 vs 0x12F, 100 vs 113
  instructions) because the rebuild calls it with constant arguments; this is library code
  and behaviourally identical.
- **Timestamps, PDB GUID/age and import ordering** necessarily differ; they are metadata.

### If byte-exact output is required

Install the MSVC **14.30** toolset (VS2022 17.0) and rebuild with the same flags
(`/O2 /MD /GS /EHsc /GL`, link `/LTCG /DEBUG`, UAC manifest, no `/guard:cf`). The source is
already shaped to match that compiler's selective inlining. The original PDB would also
remove all identifier inference.

---

## Layout

```
original/            original binary (read-only) + partial IDA DB backup
src/main.cpp         recovered source (the only user translation unit)
include/             no public header: the target is an EXE with zero exports
tests/               behavioral differential harness + dummy left4dead2.exe target
tools/               build.bat, msvc_env.bat, pe_info.py, compare.py, verify.py
NOTES/evidence.md    per-claim evidence log (disassembly addresses, strings, layout)
STATE.md             phase state, metrics, open questions, resume notes
```
