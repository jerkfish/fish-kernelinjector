@echo off
setlocal
call "%~dp0..\msvc_env.bat"
cd /d "%~dp0..\.."
if not exist build_makeunique mkdir build_makeunique
cl /nologo /O2 /Ob1 /GL /MD /GS /EHsc /DNDEBUG /DWIN32 /D_WINDOWS ^
   /Fe:build_makeunique\SKernelInjector.exe /Fobuild_makeunique\main.obj tools\experiments\main_makeunique.cpp ^
   /link /LTCG /SUBSYSTEM:CONSOLE /DEBUG /PDB:build_makeunique\SKernelInjector.pdb ^
   /MANIFEST:EMBED "/MANIFESTUAC:level='requireAdministrator' uiAccess='false'" ^
   /MAP:build_makeunique\SKernelInjector.map
if errorlevel 1 exit /b 1
echo BUILD OK
