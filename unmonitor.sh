#!/bin/bash
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi
echo "Enter WiFi device name to put in managed mode: "
read device
systemctl unmask wpa_supplicant.service
systemctl restart wpa_supplicant.service
ip link set $device down
iw dev $device set type managed
ip link set $device up
state=$(iw dev $device info | grep type | cut -d " " -f 2)
state=$(echo -e "${state}" | tr -d '[:space:]')
if [ "$state" == "managed" ]; then
	echo "Successfully put $device in managed mode"
else
	echo "Failed to put $device in managed mode"
fi
