@echo off
setlocal
call "%~dp0..\msvc_env.bat"
cd /d "%~dp0..\.."
if not exist build_nocfg mkdir build_nocfg
cl /nologo /O2 /Ob1 /GL /MD /GS /EHsc /DNDEBUG /DWIN32 /D_WINDOWS ^
   /Fe:build_nocfg\SKernelInjector.exe /Fobuild_nocfg\main.obj src\main.cpp ^
   /link /LTCG /SUBSYSTEM:CONSOLE /DEBUG /PDB:build_nocfg\SKernelInjector.pdb ^
   /MANIFEST:EMBED ^
   "/MANIFESTUAC:level='requireAdministrator' uiAccess='false'" ^
   /MAP:build_nocfg\SKernelInjector.map
if errorlevel 1 exit /b 1
echo BUILD OK
