#!/usr/bin/bash

# Written By AuxGrep
# 2023

# Update the package list and upgrade existing packages
sudo apt-get update
sudo apt-get upgrade -y

# Install required packages
sudo apt-get install -y golang make git python3 python3-pip wget

# Install MongoDB
echo "Installing MongoDB"
wget -qO - "https://www.mongodb.org/static/pgp/server-4.2.asc" | sudo apt-key add -
sudo apt-get update
sudo apt-get install -y mongodb-org
sudo systemctl start mongod
sudo systemctl daemon-reload
sudo systemctl enable mongod

# Install Rita Intelligence Threat Analytics
echo "Installing Rita Intelligence Threat Analytics"
cd rita
make
sudo make install
sudo mkdir /etc/rita
sudo chmod 755 /etc/rita
sudo mkdir -p /var/lib/rita/logs
sudo chmod -R 755 /var/lib/rita
sudo cp etc/rita.yaml /etc/rita/config.yaml
sudo chmod 666 /etc/rita/config.yaml
rita test-config

# Install Zeek and Zeek-cut
echo "Installing Zeek and Zeek-cut"
sudo apt-get install -y cmake make gcc g++ flex libfl-dev bison libpcap-dev libssl-dev python3 python3-dev swig zlib1g-dev
sudo apt-get install -y zeek
cd ../zeek-aux
sudo ./configure
sudo make
sudo make install
sudo updatedb
sudo cp /usr/local/zeek/bin/zeek-cut /usr/bin
