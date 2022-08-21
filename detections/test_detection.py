from detections.base_detection import BaseDetection

class TestDetection(BaseDetection):
    def __init__(self,packet_array):
        super().__init__(packet_array)
    
    def start_detection(self):
        self.in_progress = True
        for packet in self.packet_array:
            if not self.stopped:
                try:
                    if packet.addr2 == "84:a1:d1:d5:ac:d0":
                        print("suspicious packet detected")
                        self.detection_result = True
                        self.suspected_packets_array.append(packet)
                except: 
                    pass 
            else:
                self.in_progress = False
                return 
        self.in_progress = False