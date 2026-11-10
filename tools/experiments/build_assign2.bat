@echo off
setlocal
call "%~dp0..\msvc_env.bat"
cd /d "%~dp0..\.."
if not exist build_assign2 mkdir build_assign2
cl /nologo /O2 /Ob1 /GL /MD /GS /EHsc /DNDEBUG /DWIN32 /D_WINDOWS ^
   /Fe:build_assign2\SKernelInjector.exe /Fobuild_assign2\main.obj tools\experiments\main_assign2.cpp ^
   /link /LTCG /SUBSYSTEM:CONSOLE /DEBUG /PDB:build_assign2\SKernelInjector.pdb ^
   /MANIFEST:EMBED "/MANIFESTUAC:level='requireAdministrator' uiAccess='false'" ^
   /MAP:build_assign2\SKernelInjector.map
if errorlevel 1 exit /b 1
echo BUILD OK
