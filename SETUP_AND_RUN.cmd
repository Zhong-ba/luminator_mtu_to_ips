@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"

echo Luminator MTU to IPS Converter
echo Auto-detecting Jet/DAO bitness and matching Python...
echo.

set "DAO32=0"
set "DAO64=0"
set "DAO32INFO="
set "DAO64INFO="

if exist "%WINDIR%\SysWOW64\cscript.exe" (
  "%WINDIR%\SysWOW64\cscript.exe" //nologo "%~dp0PROBE_DAO.vbs" > "%TEMP%\luminator_dao32.txt" 2>&1
  if not errorlevel 1 set "DAO32=1"
  set /p DAO32INFO=<"%TEMP%\luminator_dao32.txt"
)
if exist "%WINDIR%\System32\cscript.exe" (
  "%WINDIR%\System32\cscript.exe" //nologo "%~dp0PROBE_DAO.vbs" > "%TEMP%\luminator_dao64.txt" 2>&1
  if not errorlevel 1 set "DAO64=1"
  set /p DAO64INFO=<"%TEMP%\luminator_dao64.txt"
)

> launcher_diagnostics.txt echo Luminator MTU to IPS Converter launcher diagnostics
>>launcher_diagnostics.txt echo DAO32=%DAO32%
>>launcher_diagnostics.txt echo DAO64=%DAO64%
>>launcher_diagnostics.txt echo ----- 32-bit DAO probe -----
if exist "%TEMP%\luminator_dao32.txt" type "%TEMP%\luminator_dao32.txt" >> launcher_diagnostics.txt
>>launcher_diagnostics.txt echo ----- 64-bit DAO probe -----
if exist "%TEMP%\luminator_dao64.txt" type "%TEMP%\luminator_dao64.txt" >> launcher_diagnostics.txt

echo DAO availability: 32-bit=%DAO32%  64-bit=%DAO64%
echo.

where py >nul 2>&1
if errorlevel 1 (
  echo Python launcher ^(py.exe^) was not found.
  echo Install Python for Windows and rerun this file.
  pause
  exit /b 1
)

set "PYEXE="
set "WANTEDBITS="

rem Prefer a Python whose bitness can actually instantiate DAO.
if "%DAO32%"=="1" if "%DAO64%"=="0" set "WANTEDBITS=32"
if "%DAO64%"=="1" if "%DAO32%"=="0" set "WANTEDBITS=64"

if "%WANTEDBITS%"=="32" (
  py -3-32 -c "import sys" >nul 2>&1
  if errorlevel 1 (
    echo This computer has 32-bit Jet/DAO but no 32-bit Python 3.
    echo.
    echo Your current 64-bit Python cannot load a 32-bit DAO COM server.
    echo Install 32-bit Python 3 ^(it can coexist with 64-bit Python^), then rerun this file.
    echo Make sure the Python Launcher option is enabled during installation.
    >>launcher_diagnostics.txt echo RESULT=NEED_32BIT_PYTHON
    pause
    exit /b 2
  )
  for /f "usebackq delims=" %%P in (`py -3-32 -c "import sys; print(sys.executable)"`) do set "PYEXE=%%P"
)

if "%WANTEDBITS%"=="64" (
  py -3-64 -c "import sys" >nul 2>&1
  if not errorlevel 1 for /f "usebackq delims=" %%P in (`py -3-64 -c "import sys; print(sys.executable)"`) do set "PYEXE=%%P"
)

if not defined PYEXE (
  rem Both DAO bitnesses exist, or neither probe succeeded. Prefer default Python,
  rem but verify it can actually Dispatch DAO before launching the GUI.
  for /f "usebackq delims=" %%P in (`py -c "import sys; print(sys.executable)"`) do set "PYEXE=%%P"
)

if not exist "%PYEXE%" (
  echo Could not resolve a usable Python executable.
  pause
  exit /b 1
)

for %%P in ("%PYEXE%") do set "PYWEXE=%%~dpPpythonw.exe"
if not exist "%PYWEXE%" set "PYWEXE=%PYEXE%"

>>launcher_diagnostics.txt echo PYEXE=%PYEXE%
>>launcher_diagnostics.txt echo PYWEXE=%PYWEXE%
"%PYEXE%" -c "import sys,struct,site,platform; print('version='+sys.version.replace(chr(10),' ')); print('bits='+str(struct.calcsize('P')*8)); print('executable='+sys.executable); print('user_site='+str(site.getusersitepackages())); print('platform='+platform.platform())" >> launcher_diagnostics.txt 2>&1

echo Using Python:
echo   %PYEXE%
"%PYEXE%" -c "import sys,struct; print('  Python',sys.version.split()[0],'-',struct.calcsize('P')*8,'bit')"
echo.

"%PYEXE%" -c "import tkinter" >nul 2>&1
if errorlevel 1 (
  echo Tkinter is unavailable in this Python installation.
  pause
  exit /b 1
)

"%PYEXE%" -c "import win32com.client, pythoncom; from win32com.client import Dispatch, VARIANT; print(win32com.client.__file__); print(pythoncom.__file__); print('VARIANT_OK')" >> launcher_diagnostics.txt 2>&1
if errorlevel 1 (
  echo Installing pywin32 into this exact Python...
  "%PYEXE%" -m pip install --upgrade pywin32
  if errorlevel 1 (
    echo pywin32 installation failed. See launcher_diagnostics.txt.
    pause
    exit /b 1
  )
  "%PYEXE%" -m pywin32_postinstall -install >nul 2>&1
  "%PYEXE%" -c "import win32com.client, pythoncom; from win32com.client import Dispatch, VARIANT; print(win32com.client.__file__); print(pythoncom.__file__); print('VARIANT_OK')" >> launcher_diagnostics.txt 2>&1
  if errorlevel 1 (
    echo pywin32 installed but the exact imports required by the converter still fail.
    echo Send launcher_diagnostics.txt.
    pause
    exit /b 1
  )
)

rem Final critical test: can THIS Python bitness instantiate Jet/DAO?
"%PYEXE%" "%~dp0CHECK_DAO_PYTHON.py" >> launcher_diagnostics.txt 2>&1
if errorlevel 1 (
  echo.
  echo Python and pywin32 are OK, but this Python cannot open Jet/DAO.
  echo See launcher_diagnostics.txt for the exact COM error.
  if "%DAO32%"=="1" echo If this is 64-bit Python, install 32-bit Python and rerun SETUP_AND_RUN.cmd.
  pause
  exit /b 3
)

>>launcher_diagnostics.txt echo RESULT=OK
echo Environment check: OK
echo Starting GUI...
start "" "%PYWEXE%" "%~dp0MTU_to_IPS_GUI.pyw"
exit /b 0
