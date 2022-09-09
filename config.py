from kivy.config import Config
import sched, time
import threading
import os
from kivy.lang import Builder
from kivy.factory import Factory
from kivy.clock import Clock, mainthread
from kivy.uix.boxlayout import BoxLayout
from scapy.all import *
from detections.test_detection import TestDetection
from detections.deauth_detection import DeauthDetection
from Logger import Logger
from layouts.LeftSection import LeftSection
from layouts.LogLayout import LogLayout
from layouts.LogsListLayout import LogsListLayout
from layouts.FilterInputSection import FilterInputSection
from layouts.DetectionResultPopup import DetectionResultPopup
from kivy.uix.popup import Popup
from kivy.properties import StringProperty

DEV = "wlx28ee520b2232"
DISPLAY_LOGS = False 