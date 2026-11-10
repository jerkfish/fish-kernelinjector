@echo off
rem Deterministic x86 MSVC environment (does not rely on vcvarsall/vswhere).
rem Toolset 14.38.33130 is the closest installed compiler to the original 14.30.
set "VSTOOLS=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.38.33130"
set "SDK=C:\Program Files (x86)\Windows Kits\10"
set "SDKVER=10.0.22621.0"
set "PATH=%VSTOOLS%\bin\Hostx86\x86;%SDK%\bin\%SDKVER%\x64;%PATH%"
set "INCLUDE=%VSTOOLS%\include;%SDK%\Include\%SDKVER%\ucrt;%SDK%\Include\%SDKVER%\shared;%SDK%\Include\%SDKVER%\um;%SDK%\Include\%SDKVER%\winrt"
set "LIB=%VSTOOLS%\lib\x86;%SDK%\Lib\%SDKVER%\ucrt\x86;%SDK%\Lib\%SDKVER%\um\x86"
