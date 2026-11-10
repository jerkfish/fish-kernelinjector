@echo off
setlocal
call "%~dp0..\msvc_env.bat"
cd /d "%~dp0..\.."
if not exist build_assign mkdir build_assign
cl /nologo /O2 /Ob1 /GL /MD /GS /EHsc /DNDEBUG /DWIN32 /D_WINDOWS ^
   /Fe:build_assign\SKernelInjector.exe /Fobuild_assign\main.obj tools\experiments\main_assign.cpp ^
   /link /LTCG /SUBSYSTEM:CONSOLE /DEBUG /PDB:build_assign\SKernelInjector.pdb ^
   /MANIFEST:EMBED "/MANIFESTUAC:level='requireAdministrator' uiAccess='false'" ^
   /MAP:build_assign\SKernelInjector.map
if errorlevel 1 exit /b 1
echo BUILD OK
