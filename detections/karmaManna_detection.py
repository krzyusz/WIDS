from detections.base_detection import BaseDetection
from tools.AccessPointInfo import AccessPointInfo
from scapy.all import *

class KarmaMannaDetection(BaseDetection):               
    unique_karma_clients = []
    def __init__(self,frame_array):
        super().__init__(frame_array)

    ##BSSID and SSID of:
    enc_beacons = []
    no_enc_beacons = []
    probe_response_list = []
    BKL1 = [] #suspected frames - algorithm 1
    BKL2 = [] #suspected frames - algorithm 2
    BKL3 = [] #suspected frames - algorithm 3
    BKL4 = [] #suspected frames - algorithm 4

    def start_detection(self):
        self.in_progress = True
        #BKL1
        k=0
        for frame in self.packet_array:
            if frame.type == 0 and frame.subtype == 8:	            # IF mgmt & beacon
                if frame[RadioTap].cap.privacy == True:                    # "As observed, all forge packets only have ESS Capability and does not have any other capabilities. "
                    self.enc_beacons.append([frame.info.decode("utf-8"),frame.addr2])
                elif frame[RadioTap].cap.privacy == False:
                    self.no_enc_beacons.append([frame.info.decode("utf-8"),frame.addr2])	        # dopisac pobieranie BSSID i SSID
                    #print(frame[RadioTap].cap.privacy)
                    k+=1
            elif frame.type == 0 and frame.subtype == 5:                                    # IF mgmt & probe response
                self.probe_response_list.append(frame)
        for frame in self.probe_response_list:
            if [frame.info.decode("utf-8"),frame.addr2] not in self.no_enc_beacons:
                self.BKL1.append(frame)
                self.detection_result = True
                self.suspected_packets_array.append(frame)
        #BKL23
        for frame in self.packet_array:
            if frame.type == 0 and frame.subtype == 8:
                if frame.info.decode("utf-8") and len(frame.addr2) >= 2:
                    self.BKL2.append(frame)
                    self.detection_result = True
                    self.suspected_packets_array.append(frame)
            elif frame.type == 0 and frame.subtype == 5:
                if frame.info.decode("utf-8") and len(frame.addr2) >= 2:
                    self.BKL3.append(frame)
                    self.detection_result = True
                    self.suspected_packets_array.append(frame)
        #print("BKL1", self.BKL1[:2])
        #print("BKL2", self.BKL2)
        #print("BKL3", self.BKL3)
        #print("suspecred packets array", self.suspected_packets_array)
        print("no enc: ", self.no_enc_beacons)
        print(frame[RadioTap].cap)
        print(type(frame[RadioTap].cap))
        print("no enc frames is: ", k)
        print("length", len(self.BKL1), len(self.BKL2), len(self.BKL3), len(self.suspected_packets_array))
        self.in_progress = False

# pcaps/manna_attack.pcap
# jesli sa zaszyfrowane te ramki to capability privacy field is set to 1, jesli nie ma szyfrowania to 0
# https://www.cwnp.com/forums/posts?postNum=298700

#do dodania jak bedzie real time                
    def detection_BKL4(self):
        ssid = "random1234"
        #https://security.stackexchange.com/questions/130590/sending-probe-request-frames-receving-probe-response-scapy
        packet = RadioTap()/Dot11(type=0,subtype=4,addr1="ff:ff:ff:ff:ff:ff", addr2="00:11:22:33:44:55",addr3="ff:ff:ff:ff:ff:ff")/Dot11Elt(ID="SSID", info="")
        response = sr(packet)
        if response.type == 0 and response.type == 5:
            if response.ssid == ssid:
                BKL4.append(frame(BSSID))
