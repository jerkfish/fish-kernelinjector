# Evidence log — SKernelInjector.exe

All addresses are virtual addresses (image base 0x400000). Evidence gathered from IDA
(Hex-Rays + disassembly), the PE file bytes, and installed MSVC/SDK headers.

## 1. Identity / build fingerprint

- COFF timestamp `0x625F5BBF` → 2022-04-20 01:02:55 UTC.
- Optional header: linker 14.30, subsystem 3 (console), OS/subsystem version 6.0.
- Debug directory CodeView entry: `RSDS`, GUID `db6f12fb-a592-0d4c-ab8c-b0b62d16904c`, age 1,
  path `E:\l4d2\Win32\Release\SKernelInjector.pdb`.
  → Original tree lived on drive E:, folder `l4d2`, x86 Release, project `SKernelInjector`.
- Rich header (decoded): toolset builds 30625 / 30709 / 30729 → MSVC 14.30 (VS2022 17.0.x).
  Product IDs 255–265 belong to the VS2022-era product numbering.
- Load config `GuardFlags = 0x100` (CF_INSTRUMENTED), GuardCFCheckFunctionPointer = 0x403138,
  GuardCFFunctionTable = 0, count = 0. Interpretation: CRT startup objects (from
  `libvcruntime`) are CFG-instrumented, user objects are not. The link step did **not**
  pass `/guard:cf` (no CFG function table is emitted; see section 8.4).
  Evidence: in `__scrt_common_main_seh` at 0x40186C there is
  `call ds:___guard_check_icall_fptr` before `call esi`, while the user function at
  0x40139F has a raw `call ebx` (Process32Next).
- `.00cfg` and `.rdata$sxdata`/`.rdata$voltd` linker-added sections present; SAFESEH table at
  0x40366C with 2 entries; security cookie at 0x405004 (load config field @0x3C).
- Exception machinery: `__except_handler4` + `_except_handler4_common` (VS2015+),
  `__CxxFrameHandler3`, `__std_exception_copy/destroy`, `_CxxThrowException`.
- Manifest resource: `requireAdministrator`, no compatibility sections, no DPI awareness.

## 2. Imports (complete)

KERNEL32: OpenProcess, CreateToolhelp32Snapshot, Process32First, CloseHandle, Process32Next,
GetCurrentDirectoryA, GetProcAddress, GetModuleHandleA, VirtualAllocEx, WriteProcessMemory,
CreateRemoteThread, WaitForSingleObject, VirtualFreeEx, SetUnhandledExceptionFilter,
GetCurrentProcess, TerminateProcess, IsProcessorFeaturePresent, QueryPerformanceCounter,
GetCurrentProcessId, GetCurrentThreadId, UnhandledExceptionFilter, GetSystemTimeAsFileTime,
InitializeSListHead, IsDebuggerPresent, GetModuleHandleW.

MSVCP140: `?_Xlength_error@std@@YAXPBD@Z`.
VCRUNTIME140: __current_exception_context, __current_exception, _except_handler4_common,
__std_exception_copy, __CxxFrameHandler3, memset, __std_exception_destroy, memcpy,
_CxxThrowException, memmove.
UCRT api-sets: stdio (`_set_fmode`, `__p__commode`, `__stdio_common_vfprintf`,
`__acrt_iob_func`), conio (`_getwch`), runtime (startup/terminate/argv), string (`strcat_s`),
heap (`free`, `_callnewh`, `malloc`, `_set_new_mode`), math (`__setusermatherr`),
locale (`_configthreadlocale`).

Notably **no `strcmp` import** — the comparison inside `sub_401300` is the inline `/Oi`
strcmp intrinsic. No `printf` import — `sub_4012D0` is the UCRT header-inline `printf`.

## 3. User strings (exact bytes)

| VA | C literal |
|---|---|
| 0x4031B4 | `"left4dead2.exe"` |
| 0x4031C4 | `"\nSuccessfully injected, Please close this window!\n\n\n\n"` |
| 0x4031FC | `"\nInjection failed!\n\n\n\n"` |
| 0x403214 | `"If you experience unexpected errors, Follow the steps below:\n"` |
| 0x403254 | `"1. Dont run left4dead2.exe in compatibility mode.\n"` |
| 0x403288 | `"2. Uninstall Reshade/ENB or any d3d9 dll based mods.\n"` |
| 0x4032C0 | `"3. Disable all workshop addons.\n"` |
| 0x4032E4 | `"4. Disable anti virus softwares.\n\n"` |
| 0x403308 | `"Failed process initialization.\n"` |
| 0x403328 | `"Failed getting %s process ID, Make sure your game called left4dead2.exe\n"` |
| 0x403374 | `"\\VR.dll"` |
| 0x40337C | `"DLL Path: "` |
| 0x403388 | `"LoadLibraryA"` |
| 0x403398 | `"kernel32.dll"` |

## 4. `main` (0x401000, size 0x2B0)

Key facts from disassembly:

- `operator new(0x1C)` then full 28-byte zeroing (movups xmm0 + movq + dword) followed by
  string default-ctor fields: `[obj+0x14]=0` (size), `[obj+0x18]=15` (capacity), byte at
  `obj+4` = 0 (SSO buffer first byte). Then `std::string::assign(obj+4, "left4dead2.exe", 14)`.
  → Source: `new CProcess()` value-initialised (no user-provided ctor) and then string
  assigned. Object base = `obj`; `hProcess` at +0; `std::string` at +4.
- `call sub_401300` with `ecx = obj` → member function; reads string at `[this+4]`.
- pid==0 path: prints `"Failed getting %s ..."` with the string data pointer
  (capacity>=0x10 → heap pointer), then jumps to the shared
  `"Failed process initialization.\n"` print, then continues (no return).
- pid!=0 path: `OpenProcess(0x1FFFFF, 0, pid)` → store to `[obj+0]`; compare against
  `0xFFFFFFFF` (`INVALID_HANDLE_VALUE`), not NULL.
- `GetCurrentDirectoryA(0x104, buffer)` on a 0x104-byte stack buffer, then
  `strcat_s(buffer, 0x104, "\\VR.dll")` (template overload → 3-argument call).
- `printf("DLL Path: ")`, `printf(buffer)` (format-string bug).
- `GetModuleHandleA("kernel32.dll")`, `GetProcAddress(..., "LoadLibraryA")`.
- Single `&&` chain: `LoadLibraryA != 0 && (mem = VirtualAllocEx(...)) != 0 &&
  WriteProcessMemory(..., strlen+1, 0) && CreateRemoteThread(...) != INVALID_HANDLE_VALUE`.
  Success: `WaitForSingleObject(thread, INFINITE)`, `VirtualFreeEx(mem, 0, MEM_RELEASE)`,
  msg = success string. Else msg = failure string. One `printf(msg)`.
- Then four troubleshooting strings, `_getwch()`, destroy string (if capacity>=16 free
  buffer), `operator delete(obj, 0x1C)`, return value = `_getwch()` result (eax saved at
  `[ebp-0x118]` and loaded before epilogue).
- SEH unwind handler at 0x4023D0 deletes the object if an exception occurs after `new`.

`strlen` is inlined twice (once for VirtualAllocEx size, once for WriteProcessMemory size).

## 5. `sub_401300` (0x401300, size 0xDC) — process lookup

- `__thiscall`, `ecx = CProcess*`; string member at `this+4` (data read via +4, size +0x14,
  capacity +0x18).
- `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS=2, 0)`.
- `memset(&pe.cntUsage, 0, 0x124)` — this is `PROCESSENTRY32 pe = {};` because the compiler
  zeroes from `cntUsage` (offset 4) to end, leaving `dwSize` set next; `pe.dwSize = 296`.
- `Process32First` failure → `return 0`.
- Loop: inline strcmp of `name` vs `pe.szExeFile`; on equal → `CloseHandle(snapshot)` then
  `return pe.th32ProcessID`. `Process32Next` failure → `return 0` (snapshot not closed).
- MSVC `/Oi` strcmp intrinsic emits the 2-byte-unrolled compare loop, result normalised to
  -1/1 (`sbb eax,eax; or eax,1`), then tested for zero.
- Comparative operator still to be settled by experiment: `strcmp(a,b) == 0` vs
  `std::string == const char*`. The lack of a preceding `strlen`/length check strongly
  favours the raw `strcmp` intrinsic; empirically verified in Phase 3.

## 6. Library functions (excluded from recovery)

| Address | Identity | Evidence |
|---|---|---|
| 0x4012C0 | `__local_stdio_printf_options` | returns &unk_4053F0, value = 0xFFFFFFFFFFFFFFFF; matches UCRT `corecrt_stdio_config.h` |
| 0x4012D0 | UCRT inline `printf` | `_acrt_iob_func(1)`, `*options`, `_stdio_common_vfprintf` |
| 0x4013E0 | `std::_Xlength_error("string too long")` | MSVCP140 import + literal |
| 0x4013F0 | `std::bad_array_new_length` ctor | vftable `??_7bad_array_new_length@std@@6B@` |
| 0x401410/430 | `std::exception` dtor/scalar deleting dtor | vftable `??_7exception@std@@6B@` |
| 0x401470/4B0/500 | exception clone/ctors (`bad_array_new_length`, `bad_alloc`, `exception`) | `__std_exception_copy` |
| 0x4014F0 | `std::exception::what()` | returns "Unknown exception" when message null |
| 0x401530 | throw helper for `bad_array_new_length` | `_CxxThrowException` + `__TI3...` |
| 0x401550 | `std::string::assign(char const*, size_t)` | growth logic, `operator new`, `memcpy/memmove`, cap ≥ 0x10 |
| 0x40168E | `operator delete` | tail call `free` |
| 0x40169C | `operator new` | `malloc` + `_callnewh` + throw `bad_alloc` |
| 0x4016EF..0x401936 | CRT startup (`pre_c_initialization`, `_initterm`, `start`) | standard |
| 0x401940..0x401D84 | GS failure reporting, `find_pe_section`, startup locks, onexit, cookie init | standard |
| 0x401D85..0x402284 | startup stdio/locale/argv/SEH/`__isa_available_init` | standard |
| 0x402284..0x4023C8 | import thunks (`__CxxFrameHandler3`, memset, malloc, memcpy, ...) | standard |

RTTI globals (`??_R0/1A/2/3/4...`) and EH tables (`__TI2/3`, `__CTA2/3`, catch type infos)
all belong to `std::exception`/`std::bad_alloc`/`std::bad_array_new_length`/`type_info`.

## 7. Inferences and their evidence

| Item | Inference | Evidence / confidence |
|---|---|---|
| Target kind | EXE console program, not DLL | PE characteristics 0x0102, subsystem 3, no export dir. High |
| Language | C++ (MSVC), std::string used | `_Xlength_error` import, string layout, EH machinery. High |
| `CProcess` layout | `HANDLE hProcess; std::string name;` sizeof 0x1C | allocation size 0x1C, accesses +0/+4/+0x14/+0x18. High |
| Member function | `DWORD CProcess::GetProcessId()` (or similar) | `__thiscall` with string member accessed via this. High |
| Object creation | `new CProcess{}` value-init, owned by `std::unique_ptr` | full zeroing before ctor field writes + EH cleanup state never disarmed (section 8.1). High |
| String set | `assign("left4dead2.exe", 14)`; the original inlined `operator=` into that call | default-ctor fields written, then a direct `assign(ptr,14)` call in the binary (section 8.2). High |
| Failure structure | pid==0 prints pid message then generic init message; OpenProcess only on pid!=0 path | exact disassembly flow 0x40108D–0x4010C7. High |
| Return value | result of `_getwch()` | value stored to `[ebp-0x118]` then returned. High |
| Compiler flags | `/O2 /Ob1 /GL /MD /GS /EHsc`, link `/LTCG`, **no** link-time `/guard:cf` | fingerprint + flag experiments (section 8.4). High |
| Purpose | Console injector: loads `VR.dll` into `left4dead2.exe` via CreateRemoteThread+LoadLibraryA | strings + API sequence. High |

## 8. Phase 3 findings (source-form decisions)

### 8.1 Ownership: `std::unique_ptr<CProcess>`

Evidence that the heap object is RAII-owned rather than raw `new`/`delete`:

- `main` sets up a C++ EH frame at entry (SEH record + `__CxxFrameHandler3`), with the
  cleanup funclet at **0x4023D0** doing `push 1Ch; push [ebp-0x118]; call operator delete`.
- The EH state variable `[ebp-4]` is set to **0 after the object is allocated** (0x40103F)
  and is **never changed again** — the cleanup remains armed for the whole function. A
  new-expression construction cleanup would be disarmed right after the constructor.
- The same slot `[ebp-0x118]` holds the object pointer for the cleanup, later the
  `GetProcAddress` result, then the `_getwch` result (slot reuse proves nothing about
  ownership, but the funclet's state lifetime does).
- Rebuilding with `std::unique_ptr` reproduces the original prologue exactly:
  `push ebp/mov ebp,esp/push -1/push handler/mov eax,fs:0/push eax/sub esp,114h`,
  cookie at `[ebp-0x10]`, `mov fs:0` record, `push 0x1C`, `call operator new`,
  `mov [ebp-0x118],edi`, `mov [ebp-4],0`.
- With a raw `CProcess*` and explicit `delete`, the compiler emits **no** EH frame for this
  function (verified experimentally) — the original definitively has one.

### 8.2 String assignment inlining

- Original `main` calls `std::string::assign(char const*, size_t)` at **0x401550** with
  `(ecx = string, [esp] = "left4dead2.exe", [esp+4] = 0xE)` — the `operator=(char const*)`
  wrapper was inlined by 14.30's LTCG, the core `assign` was not.
- Installed 14.38/14.44 LTCG either keeps `operator=(char const*)` out of line (/Ob1) or
  inlines the whole assignment into SSO stores (/Ob2). Writing the recovered call as
  `szName.assign("left4dead2.exe", 14)` reproduces the original call graph (100% call
  target match in `main`) while keeping `main` at the original 0x2B0 bytes.
- Function-level evidence: 14.38 `/O2 /Ob1 /GL` main = 0x250 with raw pointer; with
  `unique_ptr` + braces + explicit assign = 0x2B0, call graph 100%, branch sites 42 vs 43.

### 8.3 Object initialization

- Original stores a 28-byte value-initialised block: `movups [edi],xmm0` (16 bytes),
  `movq [edi+0x10],xmm0` (8), `mov [edi+0x18],0` (4), then string fields. This is
  `new CProcess{}`/`new CProcess()` value-initialisation of a class with no user-provided
  constructor (the whole object is zeroed before the implicit default ctor runs).
- `new CProcess{}` with the installed compiler reproduces the exact 0x2B0 function size;
  `new CProcess()` gives 0x2C0 (same structure, slightly different stack-padding encoding).

### 8.4 Build-flag experiments (all with the 14.38 toolset)

| Flags | Result vs original |
|---|---|
| `/O2 /MD /GS /EHsc`, link `/guard:cf` | 8 sections (`.gfids`, `.00cfg`, `.idata`), CFG table, DllCharacteristics 0xC140 — rejected |
| `/O2 /GL /MD /GS /EHsc`, link `/LTCG /guard:cf` | 5 sections but CFG table + 0xC140 — rejected; also changes GetProcessId codegen (no `call ebx` hoist) |
| `/O2 /GL /MD /GS /EHsc`, link `/LTCG` (no guard) | **5 sections, DllCharacteristics 0x8140, GuardFlags 0x100/table 0 — matches** |
| + `/Ob1` | keeps `assign` out of line (matches original) |
| + `std::unique_ptr` + `new CProcess{}` + explicit `assign(ptr,14)` | main 0x2B0, calls 100%, GetProcessId 95.2% |

The original therefore linked **without** `/guard:cf`; the GuardCF fields come from the
CFG-instrumented static vcruntime startup objects, exactly as the rebuild reproduces.

### 8.5 Verification evidence (final build)

```
PE surface:            all PASS (i386, console, 6.0, 0x8140, 5 sections, GuardFlags 0x100)
Exports:               none / none
Manifest:              byte-identical (392 bytes)
Win32/MSVCP imports:   all present
main:                  0x2B0 vs 0x2B0, 88.2% instruction LCS, 100% call targets
GetProcessId:          0xDC vs 0xE0, 95.2% instruction LCS, 100% call targets
Behaviour (2 cases):   stdout and exit code identical (game absent / dummy game present)
```
