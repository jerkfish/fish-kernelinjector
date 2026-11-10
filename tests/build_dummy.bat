@echo off
setlocal
call "%~dp0..\tools\msvc_env.bat"
cd /d "%~dp0.."
cl /nologo /O2 /MD /GS tests\dummy_game.c /Fe:tests\bin\left4dead2.exe
if errorlevel 1 exit /b 1
echo DUMMY OK
