@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"

echo Luminator MTU to IPS Converter - 32-bit Python launcher
echo.

where py >nul 2>&1
if errorlevel 1 (
  echo Python launcher ^(py.exe^) was not found.
  pause
  exit /b 1
)

py -3-32 -c "import sys" >nul 2>&1
if errorlevel 1 (
  echo 32-bit Python 3 was not found by the Windows Python launcher.
  echo Install 32-bit Python 3, then run this file again.
  pause
  exit /b 1
)

for /f "usebackq delims=" %%P in (`py -3-32 -c "import sys; print(sys.executable)"`) do set "PYEXE=%%P"
for %%P in ("%PYEXE%") do set "PYWEXE=%%~dpPpythonw.exe"
if not exist "%PYWEXE%" set "PYWEXE=%PYEXE%"

> launcher_diagnostics_32bit.txt echo Luminator MTU to IPS Converter 32-bit launcher diagnostics
>>launcher_diagnostics_32bit.txt echo PYEXE=%PYEXE%
>>launcher_diagnostics_32bit.txt echo PYWEXE=%PYWEXE%
"%PYEXE%" -c "import sys,struct,site,platform; print('version='+sys.version.replace(chr(10),' ')); print('bits='+str(struct.calcsize('P')*8)); print('executable='+sys.executable); print('user_site='+str(site.getusersitepackages())); print('platform='+platform.platform())" >> launcher_diagnostics_32bit.txt 2>&1

echo Using Python:
echo   %PYEXE%
"%PYEXE%" -c "import sys,struct; print('  Python',sys.version.split()[0],'-',struct.calcsize('P')*8,'bit')"
echo.

"%PYEXE%" -c "import tkinter" >nul 2>&1
if errorlevel 1 (
  echo Tkinter is unavailable in this 32-bit Python installation.
  pause
  exit /b 1
)

"%PYEXE%" -c "import win32com.client, pythoncom; print(win32com.client.__file__); print(pythoncom.__file__)" >> launcher_diagnostics_32bit.txt 2>&1
if errorlevel 1 (
  echo Installing pywin32 into this exact 32-bit Python...
  "%PYEXE%" -m pip install --user --upgrade pywin32
  if errorlevel 1 (
    echo pywin32 installation failed.
    echo See launcher_diagnostics_32bit.txt.
    pause
    exit /b 1
  )
  "%PYEXE%" -m pywin32_postinstall -install >nul 2>&1
  "%PYEXE%" -c "import win32com.client, pythoncom; print(win32com.client.__file__); print(pythoncom.__file__)" >> launcher_diagnostics_32bit.txt 2>&1
  if errorlevel 1 (
    echo pywin32 installed but still cannot be imported by this 32-bit Python.
    echo Send me launcher_diagnostics_32bit.txt.
    pause
    exit /b 1
  )
)

echo pywin32 import: OK
>>launcher_diagnostics_32bit.txt echo pywin32_import=OK
start "" "%PYWEXE%" "%~dp0MTU_to_IPS_GUI.pyw"
exit /b 0
