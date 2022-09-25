from kivy.properties import StringProperty
from kivy.uix.boxlayout import BoxLayout

class FilterInputSection(BoxLayout):
    filter_string = ""
    filtered_packet_list = [] # result list after each filter iteration
    main_packet_list = [] #  list that we will be extracting from after each iteration (1st iteration = all packets from main, 2nd = filtered packets from 1st) 
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def text_validate(self,widget):
        self.filter_string = widget.text

    def run_filter(self):
        try:
            self.filtered_packet_list = [] 
            for i in range(0,len(self.parent.parent.parent.packet_list)):
                self.filtered_packet_list.append((i,self.parent.parent.parent.packet_list[i]))
            self.parent.parent.parent.reset_displayed_logs()
            filters = self.filter_string.split("|")
            for f in filters:
                filter_t = f.split(">")[0].strip()
                filter_s = f.split(">")[1].strip()
                print("type: "  + filter_t +", string: " + filter_s)
                if filter_t == "id":
                    self.id_filter(filter_s)
                elif filter_t == "src":
                    self.source_filter(filter_s)
                elif filter_t == "dst":
                    self.dest_filter(filter_s)
                else:
                    pass
            
            for t in self.filtered_packet_list:
                self.parent.parent.parent.add_log(str(t[0]),t[1])
        except Exception as e:
            print(e)
    
    def id_filter(self,filter_string):
        try:
            self.main_packet_list = self.filtered_packet_list
            self.filtered_packet_list = []
            logs_ranges = filter_string.split(",")
            for lr in logs_ranges:
                lr_as_array = lr.split("-")
                for i in self.main_packet_list:
                    if int(lr_as_array[0]) <= i[0] <= int(lr_as_array[1]):
                        self.filtered_packet_list.append(i)
        except Exception as ex:
            print(ex)

    def source_filter(self,filter_string):
        self.main_packet_list = self.filtered_packet_list
        self.filtered_packet_list = []
        source_ips = filter_string.split(",")
        for i in self.main_packet_list:
            for src_ip in source_ips:
                try:
                    if i[1].addr2 == src_ip:
                        self.filtered_packet_list.append(i)
                except Exception as ex:
                    print(ex)

    def dest_filter(self,filter_string):
        self.main_packet_list = self.filtered_packet_list
        self.filtered_packet_list = []
        dest_ips = filter_string.split(",")
        for i in self.main_packet_list:
            for dst_ip in dest_ips:
                try:
                    if i[1].addr1 == dst_ip:
                        self.filtered_packet_list.append(i)
                except Exception as ex:
                    print(ex)

