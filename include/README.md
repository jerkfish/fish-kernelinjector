# No public header

`SKernelInjector.exe` is a console executable with **zero exports, no DLL entry point and
no public ABI** (the export data directory is absent). There is therefore no public
interface to declare here.

The only cross-boundary contracts are:

- process stdout/stderr text (verified byte-identical against the original),
- the process exit code (the `_getwch()` key code returned by `main`),
- Win32 side effects (Toolhelp32 enumeration; `OpenProcess` + remote-thread injection into
  `left4dead2.exe` of `<cwd>\VR.dll`).
