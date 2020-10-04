#!/bin/bash
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi
echo "Enter WiFi device name to put in monitor mode: "
read device
ip link set $device down
iw dev $device set type monitor
ip link set $device up
echo $device "in monitor mode"
