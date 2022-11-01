from detections.base_detection import BaseDetection
from math import ceil
from scapy.all import *
import pprint
import binascii

class KrackDetection(BaseDetection):               
    message_3_sent_pairs = []           ## source_destination format string
    def __init__(self,packet_array):
        super().__init__(packet_array)
    
    def start_detection(self):
        self.in_progress = True
        for packet in self.packet_array:                                       
            if packet.type == 2 and packet.subtype == 8:                      # QoS Data, contains EAPOL 
                try:
                    print()
                    if str(packet[EAPOL].type) == "3":                         # EAPOL key
                            if binascii.hexlify(bytes(packet[Raw]))[2:6] == b'13ca':    # message 3, Key ACK set, Key MIC set, Encrypted Key Data set
                                print("Message 3") 
                                if str(packet.addr2) + "_" + str(packet.addr1) not in self.message_3_sent_pairs:
                                    self.message_3_sent_pairs.append(str(packet.addr2) + "_" + str(packet.addr1))
                                else:
                                    print("Message 3 retransmission. Suspected Key Reinstallation Attack")
                                    self.suspected_packets_array.append(packet)
                                    self.detection_result = True        
                                    pprint.pprint(packet)    
                            elif binascii.hexlify(bytes(packet[Raw]))[2:6] == b'010a':  # message 2, 4 way handshake initiated again, clear table data  
                                if str(packet.addr2) + "_" + str(packet.addr1) in self.message_3_sent_pairs: 
                                    self.message_3_sent_pairs.remove(str(packet.addr2) + "_" + str(packet.addr1))
                except Exception as e:
                    pass
        self.in_progress = False