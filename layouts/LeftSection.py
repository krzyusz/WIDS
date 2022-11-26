from kivy.properties import StringProperty
from kivy.uix.boxlayout import BoxLayout
from layouts.InsertFilenamePopup import InsertFilenamePopup
from kivy.uix.popup import Popup

class LeftSection(BoxLayout):
    listening = False
    tp = StringProperty("Start listening")
    total_logs = StringProperty("1000")
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
    def gather_logs(self):
        if self.listening:
            print("Stop listening")
            self.parent.parent.stop = True
            self.parent.parent.e.set()
            self.listening = False
            self.tp = "Start listening"
        else:
            print("Start listening")
            self.parent.parent.stop = False
            self.parent.parent.e.clear()
            self.parent.parent.start_second_thread()
            self.listening = True
            self.tp = "Stop listening"

    def reset_logs(self):
        self.parent.parent.reset_logs()

    def open_save_logs(self):
        show = InsertFilenamePopup()
        show.set_type("save",self)
        popupWindow = Popup(title="Save logs", content=show, size_hint=(None,None),size=(600,300))
        popupWindow.open()
    
    def save_logs(self,filename):
        self.parent.parent.start_saving(filename)

    def open_load_logs(self):
        show = InsertFilenamePopup()
        show.set_type("load",self)
        popupWindow = Popup(title="Load logs", content=show, size_hint=(None,None),size=(600,300))
        popupWindow.open()

    def load_logs(self,filename):
        self.parent.parent.load_logs(filename)

    def run_test_detection(self):
        self.parent.parent.run_test_detection()

    def run_live_detection(self):
        self.parent.parent.run_live_detection()

    def feed_ap_info(self):
        self.parent.parent.feed_ap_info()
