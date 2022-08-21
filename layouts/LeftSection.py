from kivy.properties import StringProperty
from kivy.uix.boxlayout import BoxLayout

class LeftSection(BoxLayout):
    listening = False
    tp = StringProperty("Start listening")
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

    def save_logs(self):
        self.parent.parent.start_saving()

    def load_logs(self):
        self.parent.parent.load_logs()

    def run_test_detection(self):
        self.parent.parent.run_test_detection()
