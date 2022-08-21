import os
import sys
from scapy.utils import wrpcap

class Logger():
    def save_to_pcap(self, packet_list, filename):
        wrpcap(filename,packet_list)
    def set_monitor_mode(self, dev):
        print("Trying to set monitor mode for device " + dev + "...")
        os.system("ifconfig " + dev + " down")
        os.system("iwconfig " + dev + " mode monitor")
        os.system("ifconfig " + dev + " up")
        print("Done. If you don't see any data, the monitor mode setup may have failed.")