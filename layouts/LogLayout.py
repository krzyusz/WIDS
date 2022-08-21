from kivy.uix.behaviors import ButtonBehavior
from kivy.uix.boxlayout import BoxLayout
from kivy.properties import StringProperty, ListProperty
from scapy.all import Dot11
import packet_decoder

class LogLayout(ButtonBehavior, BoxLayout):
    lid = StringProperty("1")
    src = StringProperty("src")
    dst = StringProperty("dst")
    ltype = StringProperty("ltype")
    lsubtype = StringProperty("lsubtype")
    background = ListProperty([.9, .9, .9, 1])
    packet = None
    packet_raw = None
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
    def set_parameters(self,lid,packet):
        self.packet_raw = packet
        if packet.haslayer(Dot11):
            try:
                self.lid = lid
                self.packet = packet.show(dump=True)
                self.src = packet.addr2
                self.dst = packet.addr1
                self.ltype = packet_decoder.decode_packet_type(packet.type)
                self.lsubtype = packet_decoder.decode_packet_subtype(packet.type, packet.subtype)
            except:
                pass
        else:
            self.lid = lid
            self.packet = packet.show(dump=True)
            self.src = "Err"
            self.dst = "Err"
            self.ltype = "Err"
            self.lsubtype = "Err"
            print("No dot11 layer")
    def on_press(self):
        self.parent.reset_pressed()
        self.background = [.4, .7, .5, 1]
        self.parent.log_pressed(self)

    def on_release(self):
        self.parent.parent.parent.parent.parent.parent.display_log_details(self.packet)
        #self.packet_raw.pdfdump('test.pdf')
    
    def reset_pressed(self):   
        self.background = [.9, .9, .9, 1]
        