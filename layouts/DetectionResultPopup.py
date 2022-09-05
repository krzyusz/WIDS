from scapy.all import Dot11
import packet_decoder
from kivy.uix.boxlayout import BoxLayout
from layouts.LogLayout import LogLayout

class DetectionResultPopup(BoxLayout):
    packets_list = []
    suspicious_packets_list = []
    counter = 0
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def load_sets(self,packets,suspicious_packets):
        self.packets_list = packets
        self.suspicious_packets_list = suspicious_packets

    def fill_widgets(self):
        for packet in self.packets_list:
            log_l = self.get_log_layout(packet)
            self.ids.logs.add_widget(log_l)
            if len(self.suspicious_packets_list) > 0:
                for s_packet in self.suspicious_packets_list:
                    if packet == s_packet:
                        log_l.background = [.8, .3, .2, 1]
                        log_l.src = packet.addr2
                        break    
            self.counter += 1 

    def get_log_layout(self,packet):
        log_layout = LogLayout()
        if packet.haslayer(Dot11):
            try:
                log_layout.lid = str(self.counter)
                log_layout.packet = packet.show(dump=True)
                log_layout.src = packet.addr2
            except Exception as e:
                log_layout.src = " "
            try:
                log_layout.dst = packet.addr1
                log_layout.ltype = packet_decoder.decode_packet_type(packet.type)
                log_layout.lsubtype = packet_decoder.decode_packet_subtype(packet.type, packet.subtype)
            except Exception as e:
                pass
            
        else:
            log_layout.lid = str(self.counter)
            log_layout.packet = packet.show(dump=True)
            log_layout.src = "Err"
            log_layout.dst = "Err"
            log_layout.ltype = "Err"
            log_layout.lsubtype = "Err"
        return log_layout
