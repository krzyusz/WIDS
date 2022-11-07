from detections.base_detection import BaseDetection
from tools.AccessPointInfo import AccessPointInfo
from scapy.all import *
import sys, datetime


class CTSFlood(BaseDetection):               
    def __init__(self,frame_array):
        super().__init__(frame_array)

    def start_detection(self):
        THRESH =(25/5)
        START = 5
        start = datetime.datetime.now()
        rtsCNT = 0
        ctsCNT = 0
        delta = datetime.datetime.now()-start
        self.in_progress = True
        for frame in self.packet_array:
            if frame.type == 1 and frame.subtype == 12:     #type control and subtype CTS
                ctsCNT += 1
                if delta.seconds > START and ctsCNT/delta.seconds > THRESH:
                    print("Detected CTS Flood. \n")
                    self.detection_result = True
                    self.suspected_packets_array.append(frame)
            elif frame.type ==1 and frame.subtype == 11:    #type control and subtype RTS
                rtsCNT += 1
                if delta.seconds > START and rtsCNT/delta.seconds > THRESH:
                    print("Detected RTS Flood. \n")
                    self.detection_result = True
                    self.suspected_packets_array.append(frame)
        start = datetime.datetime.now()
        self.in_progress = False


# Based on: Detecting and Responding to Data Link Layer Attacks, TJ OConnor, 2021 SANS Institute
# pcaps/cts_flood.pcap