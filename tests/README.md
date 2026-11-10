# Behavioral differential tests

`behavior_test.py` compares `original/SKernelInjector.exe` with
`build/SKernelInjector.exe` at the process level.

## How it works

Both binaries have `requestedExecutionLevel='requireAdministrator'` in their manifest, so
they are started with `__COMPAT_LAYER=RunAsInvoker` to avoid a UAC prompt.

The programs end with `_getwch()` ("press any key"), which cannot be fed deterministically
from a headless harness (a console race can make `_getwch` consume unrelated input). The
suite therefore calls `tests/make_test_copies.py`, which writes
`tests/bin/original_noinput.exe` and `tests/bin/rebuilt_noinput.exe`: in each copy the
**single `call _getwch` instruction** is replaced with `mov eax, 120; nop` (120 == `'x'`).
Every other byte is identical to the shipped binary. The copies exit immediately with the
same return value the real program produces after pressing `x`, so stdout and exit code
(120) can be compared deterministically.

## Scenarios

1. **game absent** — no `left4dead2.exe` is running. The test asserts the PID-failure and
   "Injection failed!" output and that the success banner is absent.
2. **game present** — a fresh `tests/bin/left4dead2.exe` dummy is started for **each**
   binary run (and killed afterwards). The injector finds it, opens it, allocates/writes
   the DLL path, creates the remote thread and prints the success banner; the test asserts
   that branch. `VR.dll` intentionally does not exist: the injector reports success on
   remote-thread creation, like the original.

## Safety

If any process named `left4dead2.exe` is already running, the suite **refuses to run**
rather than injecting into a real game. The dummy is a normal, non-elevated 32-bit process
owned by the current user; the injected `LoadLibraryA` call fails because `VR.dll` is
absent. Nothing is installed or persisted.

## Prerequisites

```bat
tests\build_dummy.bat     :: creates tests\bin and builds tests\bin\left4dead2.exe
tools\build.bat           :: builds build\SKernelInjector.exe
```

## Run

```bat
python tests\behavior_test.py
```

Exit code 0 = both scenarios PASS. Three consecutive runs pass deterministically.
