@echo off

echo Updating pip...
python -m pip install --upgrade pip

echo Installing Python dependencies...
python -m pip install requests beautifulsoup4 dnspython whois scapy

echo Installation completed.
pause
