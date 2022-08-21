from kivy.uix.stacklayout import StackLayout
from layouts.LogLayout import LogLayout

class LogsListLayout(StackLayout):
    lastPressed = None
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
    def add_log(self,lid,packet):
        ll = LogLayout()
        ll.set_parameters(lid,packet)
        self.add_widget(ll)
    def reset_logs(self):
        self.clear_widgets()
    def log_pressed(self,logLayout):
        try:
            self.lastPressed = logLayout
        except:
            pass
    def reset_pressed(self):
        try:
            self.lastPressed.reset_pressed()
            self.lastPressed = None
        except:
            pass