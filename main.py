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
    LIVE_RUNNING = False

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
        print("shalom")
        self.ctr += 1
        self.packet_list.append(pkt)
        self.total_logs = str(self.ctr) 
        if DISPLAY_LOGS:
            print("shalom2")
            self.add_log(str(self.ctr),pkt)

        detections_list=[DeauthDetection([]), MissmatchFieldsDetection([]),
        SpoofedFramesDetection([]), KarmaMannaDetection([]),
        CTSFlood([]), fakeAP([])]
        print("shalom3")
        if self.LIVE_RUNNING == True:
            print("shalom4")
            if self.ctr%100==0:
                print("petla 1")
                print(self.ctr)
                for detection in detections_list:
                    print("petla 2")
                    if detection.in_progress:
                        print(detection, "in progres")
                        continue
                    else:
                        print("Wykrywanie", detection, '\n')
                        detection.packet_array = self.packet_list[self.ctr-200:self.ctr]
                        detection.start_detection_thread()         

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

    def run_live_detection(self):
        self.LIVE_RUNNING = ~self.LIVE_RUNNING
        print("dla debugu", bool(self.LIVE_RUNNING))
        

    def feed_ap_info(self):
        self.ap_info.load_frames(self.packet_list)
        self.ap_info.get_app_info_from_frames()
        self.ap_info.save_ap_info_to_file()

class WIDSApp(App):
    pass

WIDSApp().run() 
