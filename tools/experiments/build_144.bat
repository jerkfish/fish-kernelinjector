@echo off
setlocal
set "VSTOOLS=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207"
call "%~dp0..\msvc_env.bat"
cd /d "%~dp0..\.."
if not exist build_144 mkdir build_144
cl /nologo /O2 /Ob1 /GL /MD /GS /EHsc /DNDEBUG /DWIN32 /D_WINDOWS ^
   /Fe:build_144\SKernelInjector.exe /Fobuild_144\main.obj tools\experiments\main_unique.cpp ^
   /link /LTCG /SUBSYSTEM:CONSOLE /DEBUG /PDB:build_144\SKernelInjector.pdb ^
   /MANIFEST:EMBED "/MANIFESTUAC:level='requireAdministrator' uiAccess='false'" ^
   /MAP:build_144\SKernelInjector.map
if errorlevel 1 exit /b 1
echo BUILD OK
