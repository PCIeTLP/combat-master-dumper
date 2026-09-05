@echo off
setlocal
cd /d "%~dp0"

if defined VCINSTALLDIR goto :ready

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" set "VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
  echo [!] vswhere.exe not found - install Visual Studio with the C++ workload
  exit /b 1
)

set "VSPATH="
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSPATH=%%i"
if not defined VSPATH (
  echo [!] no Visual Studio install with the C++ toolset
  exit /b 1
)
call "%VSPATH%\VC\Auxiliary\Build\vcvars64.bat" >nul || exit /b 1

:ready
if not exist bin mkdir bin
if not exist obj mkdir obj

set CFLAGS=/nologo /std:c++17 /O2 /EHa /W3 /MT /DNDEBUG /D_CRT_SECURE_NO_WARNINGS /Brepro /Fo:obj\
set LFLAGS=/Brepro /emittoolversioninfo:no /incremental:no
set LIBS=psapi.lib shell32.lib ole32.lib advapi32.lib user32.lib gdi32.lib version.lib

echo [*] combat_master_dumper.dll
cl %CFLAGS% /LD src\core.cpp src\fit.cpp src\emit.cpp src\ui.cpp src\dllmain.cpp ^
   /Fe:bin\combat_master_dumper.dll /link %LFLAGS% %LIBS% /IMPLIB:obj\combat_master_dumper.lib || goto :fail

echo [*] injector.exe
cl %CFLAGS% injector\injector.cpp /Fe:bin\injector.exe /link %LFLAGS% advapi32.lib || goto :fail

echo.
echo [+] built -^> bin\
dir /b /a-d bin
exit /b 0

:fail
echo.
echo [!] build failed
exit /b 1
