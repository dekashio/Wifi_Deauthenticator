# Wifi_Deauthenticator

Description:  
- Custom Python3 WiFi Deauth Tool using Scapy.  
- Tries first PMKID attack then asks for permission to continue to deauth attack.  

Features:  
- Automatic Monitor mode.  
- Checks for dependencies and disturbing processes and services.
- Automatic Conversion to hashcat 22000 mode.  
- Automatic upload to Dropbox.  

Requirements:  
- hashcat-utils: https://github.com/hashcat/hashcat-utils V1.9 and up    
- hcxdumptool: https://github.com/ZerBea/hcxdumptool V6.1.2 and up  
- hcxtools: https://github.com/ZerBea/hcxtools V6.1.2 and up  

Installation Instructions:  
- git clone https://github.com/dekashio/Wifi_Deauthenticator  
- cd Wifi_Deauthenticator
- chmod +x install_deps.sh  
- sudo ./install_deps.sh  
- sudo python3 deauth.py -h  
  
# This tool is intended to work on Ubuntu / debian.
