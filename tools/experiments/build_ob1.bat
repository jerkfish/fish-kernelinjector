@echo off
setlocal
call "%~dp0..\msvc_env.bat"
cd /d "%~dp0..\.."
if not exist build_ob1 mkdir build_ob1
cl /nologo /O2 /Ob1 /GL /MD /GS /EHsc /DNDEBUG /DWIN32 /D_WINDOWS ^
   /Fe:build_ob1\SKernelInjector.exe /Fobuild_ob1\main.obj src\main.cpp ^
   /link /LTCG /SUBSYSTEM:CONSOLE /DEBUG /PDB:build_ob1\SKernelInjector.pdb ^
   /GUARD:CF /MANIFEST:EMBED ^
   "/MANIFESTUAC:level='requireAdministrator' uiAccess='false'" ^
   /MAP:build_ob1\SKernelInjector.map
if errorlevel 1 exit /b 1
echo BUILD OK
