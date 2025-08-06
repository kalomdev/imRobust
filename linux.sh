#!/bin/bash

echo "Updating system packages..."
sudo apt update && sudo apt upgrade -y

echo "Installing Python3 and pip if needed..."
sudo apt install -y python3 python3-pip

echo "Updating pip..."
python3 -m pip install --upgrade pip

echo "Installing Python dependencies..."
pip3 install requests beautifulsoup4 dnspython whois scapy

echo "Installation completed."
