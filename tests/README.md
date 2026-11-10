# Behavioral differential tests

`behavior_test.py` compares `original/SKernelInjector.exe` with
`build/SKernelInjector.exe` at the process level.

## How it works

Both binaries have `requestedExecutionLevel='requireAdministrator'` in their manifest, so
they are started with `__COMPAT_LAYER=RunAsInvoker` to avoid a UAC prompt. Each process
gets its own console (`CREATE_NEW_CONSOLE`) with stdout/stderr piped. The harness attaches
to that console, opens `CONIN$`, queues an `x` key event (VK 0x58), and lets the program's
`_getwch()` return. Stdout and the exit code (expected 120 = `'x'`) must be byte-identical
between the two binaries.

## Scenarios

1. **game absent** — no `left4dead2.exe` is running. The PID lookup fails and the injection
   attempt fails (`VirtualAllocEx` with a NULL process handle).
2. **game present** — `tests/bin/left4dead2.exe` (a dummy built from `dummy_game.c`, sleeps
   15 s) is started first. The injector finds it, opens it, allocates/writes the DLL path,
   creates the remote thread and prints the success banner. `VR.dll` intentionally does not
   exist: the injector reports success on remote-thread creation, like the original.

## Prerequisites

```bat
tests\build_dummy.bat     :: builds tests\bin\left4dead2.exe with the MSVC x86 toolset
tools\build.bat           :: builds build\SKernelInjector.exe
```

## Run

```bat
python tests\behavior_test.py
```

Exit code 0 = both scenarios PASS.

## Safety

The dummy is a normal, non-elevated 32-bit process owned by the current user; the injected
`LoadLibraryA` call fails because `VR.dll` is absent. Nothing is installed or persisted.

## Console-race note

`_getwch()` and the per-process console setup can race in headless sessions. The harness
gives each child an owned stdin pipe and retries a run (up to 5 times) until the key event
is delivered and the process exits with 120 (`'x'`). Three consecutive full runs passed.
