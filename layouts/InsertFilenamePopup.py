from scapy.all import Dot11
import packet_decoder
from kivy.uix.boxlayout import BoxLayout
from layouts.LogLayout import LogLayout
from kivy.properties import StringProperty

class InsertFilenamePopup(BoxLayout):
    popup_type = "" # save or load
    filename = "manna_attack.pcap"
    button_text = StringProperty("")
    caller = None
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def set_type(self, popup_type, caller):
        self.popup_type = popup_type
        self.caller = caller
        if self.popup_type == "save":
            self.button_text = "Save to file"
        elif self.popup_type == "load":
            self.button_text = "Load logs"

    def set_filename_for_operation(self, widget):
        self.filename = widget.text
    
    def run_function(self):
        if self.popup_type == "save":
            self.caller.save_logs(self.filename)
        elif self.popup_type == "load":
            self.caller.load_logs(self.filename)

    
