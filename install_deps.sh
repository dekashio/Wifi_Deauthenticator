#!/bin/bash

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

INSTALL_DIR=$(pwd)/

#install os deps:
apt install python3-pip git libcurl4-openssl-dev libssl-dev make tshark zlib1g-dev -qq -y
#get tools sources from github, compile them  and install to PATH:
git clone https://github.com/hashcat/hashcat-utils
cd hashcat-utils/src/
make -j $(nproc)
cp cap2hccapx.bin /usr/local/bin/
cd $INSTALL_DIR
git clone https://github.com/ZerBea/hcxdumptool
cd hcxdumptool
make -j $(nproc)
make install
cd $INSTALL_DIR
git clone https://github.com/ZerBea/hcxtools
cd hcxtools
make -j $(nproc)
make install
cd $INSTALL_DIR
#get python3 deps:
pip3 install dropbox pyshark scapy
