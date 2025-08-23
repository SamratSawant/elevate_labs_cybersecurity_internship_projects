@echo off
echo Installing Network Packet Sniffer for Windows...

REM Check Python version
python --version
if errorlevel 1 (
    echo Python not found! Please install Python 3.7+ first.
    pause
    exit /b 1
)

REM Install Python packages
echo Installing Python packages...
pip install scapy matplotlib Pillow

REM Test tkinter (should work by default)
echo Testing tkinter...
python -c "import tkinter; print('Tkinter OK')"

REM Test scapy
echo Testing scapy...
python -c "import scapy; print('Scapy OK')"

echo.
echo Installation complete!
echo.
echo IMPORTANT: You need to install Npcap manually:
echo 1. Download from: https://npcap.com/dist/
echo 2. Run as Administrator
echo 3. Check 'WinPcap API-compatible Mode'
echo.
pause
