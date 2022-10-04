from detections.base_detection import BaseDetection
from tools.AccessPointInfo import AccessPointInfo
from scapy.all import *

class SpoofedFramesDetection(BaseDetection):            
    def __init__(self,packet_array):
        super().__init__(packet_array)
    
    def start_detection(self):
        self.in_progress = True
        for frame in self.packet_array:  
            if frame.type == 0 and frame.subtype == 12: # Deauth
                if frame[Dot11Deauth].reason == 7: # class 3 frame received from nonassociated STA
                    self.detection_result = True
                    self.suspected_packets_array.append(frame)        
                    print("Suspicious deauth frame: Deauth reason - class 3 frame received from nonassociated STA")

        self.in_progress = False