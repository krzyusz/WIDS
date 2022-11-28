from detections.base_detection import BaseDetection
from tools.AccessPointInfo import AccessPointInfo
from scapy.all import *
import sys, datetime, scapy

class fakeAP(BaseDetection):               
    def __init__(self,frame_array):
        super().__init__(frame_array)

    def start_detection(self):
        THRESH = 5
        ssidDict = {}
        ssidCnt = {}
        self.in_progress = True
        for frame in self.packet_array:
            if frame.type == 0 and frame.subtype == 8:     #type management and subtype Beacon:
                ssid = frame.info.decode("utf-8")
                bssid = frame.addr2
                stamp = frame[Dot11Beacon].timestamp #str(p.getlayer(Dot11).timestamp)
                #print(ssid, bssid, stamp, '\n')
                if bssid not in ssidDict:
                    ssidDict[bssid] = []
                    ssidCnt[bssid]=0
                elif (int(stamp) < int(ssidDict[bssid][len(ssidDict[bssid])-1])):
                    ssidCnt[bssid]=ssidCnt[bssid]+1
                    if (ssidCnt[bssid] > THRESH):
                        print("[*] - Detected fakeAP for: "+ssid)
                        self.detection_result = True
                        self.suspected_packets_array.append(frame)
                ssidDict[bssid].append(stamp)
        start = datetime.datetime.now()
        self.in_progress = False

# Based on: Detecting and Responding to Data Link Layer Attacks, TJ OConnor, 2021 SANS Institute