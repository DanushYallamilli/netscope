@echo off
REM NetScope launcher for Windows.
REM Right-click this file and choose "Run as administrator" to enable ARP scanning
REM (also install Npcap from https://npcap.com with "WinPcap API-compatible mode").
cd /d "%~dp0"
title NetScope

echo.
echo  [1/3] Checking for Python...
where python >nul 2>nul
if errorlevel 1 goto nopython
python --version
if errorlevel 1 goto nopython

echo.
echo  [2/3] Installing required packages (first run can take 1-3 minutes)...
echo.
python -m pip install -r requirements.txt --disable-pip-version-check
if errorlevel 1 (
  echo.
  echo  Package installation failed. Check your internet connection and the error above.
  pause
  exit /b 1
)

echo.
echo  [3/3] Starting NetScope. Keep this window open while you use it.
python run.py
echo.
echo  NetScope has stopped.
pause
exit /b 0

:nopython
echo.
echo  Python was not found.
echo  Install it from https://www.python.org/downloads/ and tick "Add Python to PATH"
echo  during setup, then run this file again.
echo.
echo  If Windows opens the Microsoft Store instead, turn off the "python.exe" and
echo  "python3.exe" app execution aliases in Settings ^> Apps ^> Advanced app settings.
pause
exit /b 1
