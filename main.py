from kivy.app import App
from config import *
import time 
from scapy_helper import to_dict
import packet_decoder
import requests
import json

Config.set('graphics','width',1400)
Config.set('graphics','height',800)

class ByteEncoder(json.JSONEncoder):
    def default(self,obj):
        if isinstance(obj,bytes):
            return obj.decode('utf-8')
        return json.JSONEncoder.default(self,obj)

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
        test_detection = KrackDetection(self.packet_list)
        test_detection.start_detection_thread()
        
        #test_detection = DeauthDetection(self.packet_list)
        #test_detection.start_detection_thread()
        while test_detection.in_progress:
            pass 
        test_detection.print_suspected_packets()
        show = DetectionResultPopup()
        show.load_sets(self.packet_list,test_detection.suspected_packets_array)
        show.fill_widgets()
        popupWindow = Popup(title="Detection: 'Test Detection' results", content=show, size_hint=(None,None),size=(800,600))
        popupWindow.open()

    def feed_ap_info(self):
        self.ap_info.load_frames(self.packet_list)
        self.ap_info.get_app_info_from_frames()
        self.ap_info.save_ap_info_to_file()

    def send_to_cloud(self):
        all_frames = [] 
        counter = 0 
        url = "https://wids-api.onrender.com/add/frames"
        headers = {"Content-type":"application/json"}
        for frame in self.packet_list:
            try:
                if counter == 20:
                    req = {
                        "AgentID":1,
                        "Frames":all_frames   
                    }
                    r = requests.post(url, data=json.dumps(req, cls=ByteEncoder), headers=headers)
                    print(r.json())
                    counter = 0 
                    all_frames = []
                struct = {
                    "FrameInfo":{
                        "type":packet_decoder.decode_packet_type(frame.type),
                        "subtype":packet_decoder.decode_packet_subtype(frame.type, frame.subtype),
                        "src":str(frame.addr2),
                        "dst":str(frame.addr1),
                        "timestamp":str(frame[Dot11FCS].fcs)
                    },
                    "Timestamp":str(time.time()),
                    "AdditionalData":to_dict(frame),
                    "Label":"Not classified"
                }
                all_frames.append(struct)
                counter = counter + 1 
            except Exception as e:
                print(e)

class WIDSApp(App):
    pass

WIDSApp().run() 
