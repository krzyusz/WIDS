from kivy.app import App
from kivy.config import Config
import sched, time
import threading
from kivy.lang import Builder
from kivy.factory import Factory
from kivy.clock import Clock, mainthread
from kivy.uix.boxlayout import BoxLayout
from scapy.all import *
from detections.test_detection import TestDetection
from Logger import Logger
from layouts.LeftSection import LeftSection
from layouts.LogLayout import LogLayout
from layouts.LogsListLayout import LogsListLayout
from layouts.DetectionResultPopup import DetectionResultPopup
from kivy.uix.popup import Popup

Config.set('graphics','width',1400)
Config.set('graphics','height',800)

class MainLayout(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
    stop = False
    e = threading.Event()
    dev = "wlx28ee520b2232"
    packet_list = []
    filename = "logs.pcap"
    ctr = 0; 
    def start_second_thread(self):
        Logger().set_monitor_mode(self.dev)
        threading.Thread(target=self.start_listening).start()

    def start_saving(self):
        Clock.schedule_once(lambda cb: self.save_logs_to_file(self.filename,self.packet_list),0)

    def save_logs_to_file(self,filename,packet_list):
        Logger().save_to_pcap(packet_list,filename)

    def display_log_details(self,packet):
        self.ids.rightSection.ids.logDetailedInfoSection.ids.logDetailsLabel.text = str(packet)

    def reset_logs(self):
        self.ids.rightSection.ids.logsDisplaySection.ids.logs.reset_logs()
        self.packet_list = []
        self.ctr = 0
    
    def load_logs(self):
        self.reset_logs()
        scapy_cap = rdpcap(self.filename)
        for packet in scapy_cap:
            self.packet_handler(packet)

    @mainthread
    def add_log(self,lid,packet):
        self.ids.rightSection.ids.logsDisplaySection.ids.logs.add_log(lid,packet)

    def packet_handler(self, pkt):
        self.ctr += 1
        self.packet_list.append(pkt)
        self.add_log(str(self.ctr),pkt)

    def start_listening(self):
        for packet in sniff(iface=self.dev,stop_filter=lambda x: self.e.is_set(), prn=self.packet_handler):
            if self.stop:
                return
            
    def run_test_detection(self):
        test_detection = TestDetection(self.packet_list)
        test_detection.start_detection_thread()
        while test_detection.in_progress:
            pass 
        test_detection.print_suspected_packets()
        show = DetectionResultPopup()
        show.load_sets(self.packet_list,test_detection.suspected_packets_array)
        show.fill_widgets()
        popupWindow = Popup(title="Detection: 'Test Detection' results", content=show, size_hint=(None,None),size=(800,600))
        popupWindow.open()

class WIDSApp(App):
    pass

WIDSApp().run() 
