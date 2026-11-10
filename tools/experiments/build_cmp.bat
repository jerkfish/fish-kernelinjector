@echo off
setlocal
call "%~dp0..\msvc_env.bat"
if errorlevel 1 exit /b 1
cd /d "%~dp0..\.."
cl /nologo /O2 /MD /GS /EHsc /c tools\experiments\cmp_test.cpp /Fotools\experiments\cmp_test_1438.obj
if errorlevel 1 exit /b 1
dumpbin /nologo /disasm:nobytes tools\experiments\cmp_test_1438.obj
