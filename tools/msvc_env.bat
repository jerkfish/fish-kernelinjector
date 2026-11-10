@echo off
rem Deterministic x86 MSVC environment (does not rely on vcvarsall/vswhere).
rem Honors a caller-provided VSTOOLS/SDK/SDKVER (used by tools\experiments\build_144.bat).
rem Default: MSVC 14.38.33130 (closest installed toolset to the original 14.30).
if not defined VSTOOLS set "VSTOOLS=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.38.33130"
if not defined SDK set "SDK=C:\Program Files (x86)\Windows Kits\10"
if not defined SDKVER set "SDKVER=10.0.22621.0"
if not exist "%VSTOOLS%\bin\Hostx86\x86\cl.exe" (
    echo ERROR: MSVC x86 compiler not found under "%VSTOOLS%"
    exit /b 1
)
if not exist "%SDK%\Include\%SDKVER%\um\windows.h" (
    echo ERROR: Windows SDK %SDKVER% not found under "%SDK%"
    exit /b 1
)
set "PATH=%VSTOOLS%\bin\Hostx86\x86;%SDK%\bin\%SDKVER%\x64;%PATH%"
set "INCLUDE=%VSTOOLS%\include;%SDK%\Include\%SDKVER%\ucrt;%SDK%\Include\%SDKVER%\shared;%SDK%\Include\%SDKVER%\um;%SDK%\Include\%SDKVER%\winrt"
set "LIB=%VSTOOLS%\lib\x86;%SDK%\Lib\%SDKVER%\ucrt\x86;%SDK%\Lib\%SDKVER%\um\x86"
exit /b 0
