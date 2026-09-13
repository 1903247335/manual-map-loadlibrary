@echo off
setlocal EnableExtensions

rem Need VS x64 Developer Command Prompt / vcvars64.
rem Usage: build.bat

where cl >nul 2>&1
if errorlevel 1 (
  echo [!] cl.exe not found. Run from x64 Native Tools Command Prompt.
  exit /b 1
)

if not exist bin mkdir bin
if not exist bin\obj mkdir bin\obj

echo [*] building payload.dll ...
cl /nologo /O2 /W3 /EHsc /utf-8 /LD /DPAYLOAD_EXPORTS ^
  /Fo"bin\obj\\" /Fe"bin\payload.dll" ^
  payload\dllmain.cpp ^
  /link /OUT:"bin\payload.dll" /IMPLIB:"bin\payload.lib" user32.lib

if errorlevel 1 exit /b 1

echo [*] building injector.exe ...
cl /nologo /O2 /W3 /EHsc /utf-8 ^
  /Fo"bin\obj\\" /Fe"bin\injector.exe" ^
  injector\main.cpp injector\manual_map.cpp ^
  /link /OUT:"bin\injector.exe" user32.lib

if errorlevel 1 exit /b 1

echo.
echo [+] build ok
echo     bin\payload.dll
echo     bin\injector.exe
exit /b 0
