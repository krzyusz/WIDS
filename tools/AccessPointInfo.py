import pprint
from scapy.all import *
import json

class AccessPointInfo:
    frame_array = []
    ap_info_list = {}
    ap_names = []
    def get_app_info_from_frames(self):
        for frame in self.frame_array:
            if frame.type == 0 and frame.subtype == 8:  #beacon frames
                if frame.info.decode("utf-8") not in self.ap_names:
                    self.ap_names.append(frame.info.decode("utf-8"))
                    self.ap_info_list[frame.info.decode("utf-8")] = {}
                    self.ap_info_list[frame.info.decode("utf-8")][frame.addr2] = [frame[RadioTap].dBm_AntSignal, frame[RadioTap].ChannelFrequency, str(frame[RadioTap].ChannelFlags)]
                else:
                    if frame.addr2 not in self.ap_info_list[frame.info.decode("utf-8")]:
                        self.ap_info_list[frame.info.decode("utf-8")][frame.addr2] = [frame[RadioTap].dBm_AntSignal, frame[RadioTap].ChannelFrequency, str(frame[RadioTap].ChannelFlags)]
        pprint.pprint(self.ap_info_list)

    def save_ap_info_to_file(self):
        json.dump(self.ap_info_list,open("AP_INFO","w"))

    def load_ap_info_from_file(self):
        self.ap_info_list = json.load(open("AP_INFO"))
        for names in self.ap_info_list.keys():
            self.ap_names.append(names)
    
    def load_frames(self,frames):
        self.frame_array = frames 