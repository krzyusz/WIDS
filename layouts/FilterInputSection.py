from kivy.properties import StringProperty
from kivy.uix.boxlayout import BoxLayout

class FilterInputSection(BoxLayout):
    filter_string = ""
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def text_validate(self,widget):
        self.filter_string = widget.text
        print(self.filter_string)

    def run_filter(self):
        try:
            self.parent.parent.parent.reset_displayed_logs()
            logs = self.filter_string.split("-")
            for i in range(int(logs[0]),int(logs[1])):
                self.parent.parent.parent.add_log(str(i),self.parent.parent.parent.packet_list[i])
        except Exception as e:
            print(e)
