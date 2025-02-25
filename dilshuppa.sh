#!/bin/bash

# This script will install the necessary dependencies and set up Dilshuppa_IDS.

echo "Setting up Dilshuppa_IDS Tool by Dilshuppa..."

# Update package list and install Python3, pip, and necessary dependencies
sudo apt update

# Install Python 3 and pip if they aren't already installed
sudo apt install -y python3 python3-pip

# Install necessary Python dependencies from requirements.txt
if [ -f requirements.txt ]; then
    echo "Installing Python dependencies from requirements.txt..."
    pip3 install -r requirements.txt
else
    echo "No requirements.txt found, skipping Python dependency installation."
fi

# Install additional system dependencies if needed (e.g., tcpdump, scapy)
echo "Installing system dependencies (tcpdump, scapy)..."
sudo apt install -y tcpdump scapy

# If you want the tool to be globally accessible, you could create a symlink
echo "Creating a symlink to make the tool accessible globally..."
sudo ln -s $(pwd)/src/dilshuppa_ids.py /usr/local/bin/dilshuppa_ids

# Make the Python script executable
chmod +x src/dilshuppa_ids.py

# Confirm the setup
echo "Setup completed! You can now run the tool with the following command:"
echo "dilshuppa_ids"
