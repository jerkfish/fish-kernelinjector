@echo off
setlocal
call "%~dp0..\msvc_env.bat"
cd /d "%~dp0..\.."
if not exist build_gl mkdir build_gl
cl /nologo /O2 /GL /MD /GS /EHsc /DNDEBUG /DWIN32 /D_WINDOWS ^
   /Fe:build_gl\SKernelInjector.exe /Fobuild_gl\main.obj src\main.cpp ^
   /link /LTCG /SUBSYSTEM:CONSOLE /DEBUG /PDB:build_gl\SKernelInjector.pdb ^
   /GUARD:CF /MANIFEST:EMBED ^
   "/MANIFESTUAC:level='requireAdministrator' uiAccess='false'" ^
   /MAP:build_gl\SKernelInjector.map
if errorlevel 1 exit /b 1
echo BUILD OK
