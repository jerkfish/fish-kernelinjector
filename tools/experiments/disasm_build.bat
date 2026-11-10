@echo off
setlocal
call "%~dp0..\msvc_env.bat"
cd /d "%~dp0..\.."
dumpbin /nologo /disasm:nobytes build\SKernelInjector.exe > build\disasm.txt
