from detections.base_detection import BaseDetection
from math import ceil
#
#   Deauth Detection V1 - statistically comparing deauth frames retreived to frames send by client
#   TODO: detect broadcast deauth
#   TODO: detect deuth with reason code 7 -> this may detect a lot of other popular attacks - implement this in late stage / or just mention it
#   TODO: check deauth / auth rate in normal environment
class DeauthDetection(BaseDetection):               
    unique_deauthed_clients = []
    def __init__(self,packet_array):
        super().__init__(packet_array)
    
    def start_detection(self):
        self.in_progress = True
        for packet in self.packet_array:                                       #
            if packet.type == 0 and packet.subtype == 12:                      # add each deauthenticated client to array
                if packet.addr1 not in self.unique_deauthed_clients:           #
                    self.unique_deauthed_clients.append(packet.addr1)          #
                    print("unique address:"+packet.addr1)
        for client_address in self.unique_deauthed_clients:
            for i in range(0,ceil(len(self.packet_array)/100)):                     #
                deauth_frames_counter = 0                                           #
                frames_sent_by_client_counter = 0                                   #
                start = i*100                                                       #   divide frames into chunks, compare deauth frames to other in one chunk
                end = 0                                                             #
                if i*100+100 > len(self.packet_array):                              #
                    end = len(self.packet_array)                                    #
                else:
                    end = i*100+100
                for packet in self.packet_array[i*100:end]:
                    try:
                        if packet.type == 0 and packet.subtype == 12 and packet.addr1 == client_address:
                            deauth_frames_counter += 1
                        elif packet.addr2 == client_address: #and ((packet.type == 0 and packet.subtype != 12) or (packet.type != 0)):
                            frames_sent_by_client_counter += 1
                    except Exception as e:
                        pass # some control frames does not have sender
                print("address: " + client_address)
                print("deauth frames counter: " + str(deauth_frames_counter))
                print("sent frames counter: " + str(frames_sent_by_client_counter))
                if deauth_frames_counter > frames_sent_by_client_counter and deauth_frames_counter>2 and frames_sent_by_client_counter>2: # values below 2 may be false positives
                    for packet in self.packet_array:
                        if packet.type == 0 and packet.subtype == 12 and packet.addr1 == client_address:
                            self.detection_result = True
                            self.suspected_packets_array.append(packet)
        self.in_progress = False