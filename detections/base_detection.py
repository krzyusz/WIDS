from threading import Thread

class BaseDetection:
    packet_array = [] # analyzed dataset
    suspected_packets_array = [] # add suspicious packets to this set for further analysis 
    detection_result = False # change when algorithm decides that dataset contains attack 
    in_progress = False # change when algorithms starts / ends its work 
    stopped = False 
    def __init__(self,packet_array):
        self.packet_array = packet_array

    def start_detection(self):
        self.in_progress = True 
    
    thread = Thread()

    def start_detection_thread(self):
        self.thread = Thread(target=self.start_detection)
        self.thread.start()

    def stop_detection(self):
        self.stopped = True 
        self.in_progress = False

    def get_progress(self):
        return self.in_progress

    def return_result(self):
        if self.in_progress == false: 
            return self.detection_result
        else:
            return False
    
    def print_suspected_packets(self):
        for packet in self.suspected_packets_array:
            print(packet.summary())
