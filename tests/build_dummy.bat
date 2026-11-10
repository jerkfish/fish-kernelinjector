@echo off
setlocal
call "%~dp0..\tools\msvc_env.bat"
if errorlevel 1 exit /b 1
cd /d "%~dp0.."
if not exist tests\bin mkdir tests\bin
cl /nologo /O2 /MD /GS /Fotests\bin\dummy_game.obj tests\dummy_game.c /Fe:tests\bin\left4dead2.exe
if errorlevel 1 exit /b 1
echo DUMMY OK
