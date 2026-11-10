@echo off
setlocal
call "%~dp0..\msvc_env.bat"
cd /d "%~dp0..\.."
if not exist build_unique mkdir build_unique
cl /nologo /O2 /Ob1 /GL /MD /GS /EHsc /DNDEBUG /DWIN32 /D_WINDOWS ^
   /Fe:build_unique\SKernelInjector.exe /Fobuild_unique\main.obj tools\experiments\main_unique.cpp ^
   /link /LTCG /SUBSYSTEM:CONSOLE /DEBUG /PDB:build_unique\SKernelInjector.pdb ^
   /MANIFEST:EMBED "/MANIFESTUAC:level='requireAdministrator' uiAccess='false'" ^
   /MAP:build_unique\SKernelInjector.map
if errorlevel 1 exit /b 1
echo BUILD OK
