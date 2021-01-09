#!/bin/bash
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi
echo "Enter WiFi device name to put into managed mode: "
read -r device
ip link set "$device" down
iw dev "$device" set type managed
ip link set "$device" up
systemctl unmask wpa_supplicant.service
systemctl restart wpa_supplicant.service
state=$(iw dev "$device" info | grep type | awk '{ print $2 }' | tr -d '[:space:]')
if [ "$state" == "managed" ]; then
	echo "Successfully put $device in managed mode"
else
	echo "Failed to put $device in managed mode"
fi
