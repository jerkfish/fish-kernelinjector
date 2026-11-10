@echo off
rem Rebuild SKernelInjector.exe with the closest installed MSVC toolset (14.38).
rem Original fingerprint: MSVC 14.30 (VS2022 17.0), x86 Release, /MD, /GS, /EHsc,
rem LTCG (/GL + /LTCG), link /DEBUG, manifest requireAdministrator, NO /guard:cf.
rem
rem /Ob1 note: 14.38's LTCG inliner is more aggressive than 14.30's. With the default
rem /Ob2 it inlines the whole std::string assignment into main (main grows 0x2B0 ->
rem 0x380); /Ob1 keeps std::string::assign out of line like the original (main 0x2C0).
setlocal
call "%~dp0msvc_env.bat"
if errorlevel 1 exit /b 1
cd /d "%~dp0.."
if not exist build mkdir build
cl /nologo /O2 /Ob1 /GL /MD /GS /EHsc /DNDEBUG /DWIN32 /D_WINDOWS ^
   /Fe:build\SKernelInjector.exe /Fobuild\main.obj src\main.cpp ^
   /link /LTCG /SUBSYSTEM:CONSOLE /DEBUG /PDB:build\SKernelInjector.pdb ^
   /MANIFEST:EMBED ^
   "/MANIFESTUAC:level='requireAdministrator' uiAccess='false'" ^
   /MAP:build\SKernelInjector.map
if errorlevel 1 exit /b 1
echo BUILD OK
