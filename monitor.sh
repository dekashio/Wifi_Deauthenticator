#!/bin/bash
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi
echo "Enter WiFi device name to put in monitor mode: "
read device
systemctl stop wpa_supplicant.service
systemctl mask wpa_supplicant.service
ip link set $device down
iw dev $device set type monitor
ip link set $device up
state=$(iw dev $device info | grep type | awk '{ print $2 }' | tr -d '[:space:]')
if [ "$state" == "monitor" ]; then
	echo "Successfully put $device in monitor mode"
else
	echo "Failed to put $device in monitor mode"
fi
