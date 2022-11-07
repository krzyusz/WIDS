from kivy.app import App
from config import *

Config.set('graphics','width',1400)
Config.set('graphics','height',800)


class MainLayout(BoxLayout):
    stop = False
    e = threading.Event()
    packet_list = []
    total_logs = StringProperty("0")
    ctr = 0; 
    ap_info = AccessPointInfo()

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if os.path.exists("AP_INFO"):
            self.ap_info.load_ap_info_from_file()
            print("AP INFO LOADED")
            self.load_logs("pcaps/manna_attack.pcap")

    def start_second_thread(self):
        Logger().set_monitor_mode(DEV)
        threading.Thread(target=self.start_listening).start()

    def start_saving(self,filename):
        Clock.schedule_once(lambda cb: self.save_logs_to_file(filename,self.packet_list),0)

    def save_logs_to_file(self,filename,packet_list):
        Logger().save_to_pcap(packet_list,filename)

    def display_log_details(self,packet):
        self.ids.rightSection.ids.logDetailedInfoSection.ids.logDetailsLabel.text = str(packet)

    def reset_logs(self):
        self.ids.rightSection.ids.logsDisplaySection.ids.logs.reset_logs()
        self.packet_list = []
        self.ctr = 0

    def reset_displayed_logs(self):
        self.ids.rightSection.ids.logsDisplaySection.ids.logs.reset_logs()
    
    def load_logs(self,filename):
        self.reset_logs()
        scapy_cap = rdpcap(filename)
        for packet in scapy_cap:
            self.packet_handler(packet)

    @mainthread
    def add_log(self,lid,packet):
        self.ids.rightSection.ids.logsDisplaySection.ids.logs.add_log(lid,packet)

    def packet_handler(self, pkt):
        self.ctr += 1
        self.packet_list.append(pkt)
        self.total_logs = str(self.ctr) 
        if DISPLAY_LOGS:
            self.add_log(str(self.ctr),pkt)

    def start_listening(self):
        for packet in sniff(iface=DEV,stop_filter=lambda x: self.e.is_set(), prn=self.packet_handler):
            if self.stop:
                return
            
    def run_test_detection(self):
        test_detection = fakeAP(self.packet_list)
        test_detection.start_detection_thread()
        
        #test_detection = DeauthDetection(self.packet_list)
        #test_detection.start_detection_thread()
        #while test_detection.in_progress:
        #    pass 
        #test_detection.print_suspected_packets()
        #show = DetectionResultPopup()
        #show.load_sets(self.packet_list,test_detection.suspected_packets_array)
        #show.fill_widgets()
        #popupWindow = Popup(title="Detection: 'Test Detection' results", content=show, size_hint=(None,None),size=(800,600))
        #popupWindow.open()

    def feed_ap_info(self):
        self.ap_info.load_frames(self.packet_list)
        self.ap_info.get_app_info_from_frames()
        self.ap_info.save_ap_info_to_file()

class WIDSApp(App):
    pass

WIDSApp().run() 
