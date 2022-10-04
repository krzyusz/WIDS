from detections.base_detection import BaseDetection
from tools.AccessPointInfo import AccessPointInfo
from scapy.all import *

## !! Before using that detection you have to feed it with AccessPointInfo object !!

class MissmatchFieldsDetection(BaseDetection):
    ap_info = None                 
    def __init__(self,packet_array):
        super().__init__(packet_array)
    
    def load_ap_info(self,ap_info):
        self.ap_info = ap_info

    def start_detection(self):
        self.in_progress = True
        for frame in self.packet_array:  
            if frame.type == 0 and frame.subtype == 8:
                if frame.info.decode("utf-8") in self.ap_info.ap_names:
                    if frame.addr2 in self.ap_info.ap_info_list[frame.info.decode("utf-8")]:
                    #### ----------------------------------------------------------------> same mac address, different signal strength +/- 20dBm 
                        original_signal_strength = int(self.ap_info.ap_info_list[frame.info.decode("utf-8")][frame.addr2][0])
                        if not original_signal_strength - 20 <= int(frame[RadioTap].dBm_AntSignal) <= original_signal_strength + 20:
                            print("Possible evil twin attack for SSID: "+ frame.info.decode("utf-8") + ", MAC: " + str(frame.addr2))
                            print("original info: " + str(self.ap_info.ap_info_list[frame.info.decode("utf-8")][frame.addr2]))
                            print("possible fake ap: " + ",".join([str(frame[RadioTap].dBm_AntSignal), str(frame[RadioTap].ChannelFrequency), str(frame[RadioTap].ChannelFlags)]))
                            self.detection_result = True
                            self.suspected_packets_array.append(frame)
                    else:
                    #### ----------------------------------------------------------------> different mac address 
                        print("Possible evil twin attack for SSID: "+ frame.info.decode("utf-8"))
                        print("original info: " + str(self.ap_info.ap_info_list[frame.info.decode("utf-8")]))
                        print("possible fake ap: " + ",".join([str(frame.addr2),str(frame[RadioTap].dBm_AntSignal), str(frame[RadioTap].ChannelFrequency), str(frame[RadioTap].ChannelFlags)]))
                        self.detection_result = True
                        self.suspected_packets_array.append(frame)

        self.in_progress = False