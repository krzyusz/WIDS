_dot11_subtypes = {
    0: {  # Management
        0: "Association Request",
        1: "Association Response",
        2: "Reassociation Request",
        3: "Reassociation Response",
        4: "Probe Request",
        5: "Probe Response",
        6: "Timing Advertisement",
        8: "Beacon",
        9: "ATIM",
        10: "Disassociation",
        11: "Authentication",
        12: "Deauthentication",
        13: "Action",
        14: "Action No Ack",
    },
    1: {  # Control
        2: "Trigger",
        3: "TACK",
        4: "Beamforming Report Poll",
        5: "VHT/HE NDP Announcement",
        6: "Control Frame Extension",
        7: "Control Wrapper",
        8: "Block Ack Request",
        9: "Block Ack",
        10: "PS-Poll",
        11: "RTS",
        12: "CTS",
        13: "Ack",
        14: "CF-End",
        15: "CF-End+CF-Ack",
    },
    2: {  # Data
        0: "Data",
        1: "Data+CF-Ack",
        2: "Data+CF-Poll",
        3: "Data+CF-Ack+CF-Poll",
        4: "Null (no data)",
        5: "CF-Ack (no data)",
        6: "CF-Poll (no data)",
        7: "CF-Ack+CF-Poll (no data)",
        8: "QoS Data",
        9: "QoS Data+CF-Ack",
        10: "QoS Data+CF-Poll",
        11: "QoS Data+CF-Ack+CF-Poll",
        12: "QoS Null (no data)",
        14: "QoS CF-Poll (no data)",
        15: "QoS CF-Ack+CF-Poll (no data)"
    },
    3: {  # Extension
        0: "DMG Beacon",
        1: "S1G Beacon"
    }
}

def decode_packet_type(pkt_type):
    if pkt_type == 0:
        return "Management"
    elif pkt_type == 1:
        return "Control"
    elif pkt_type == 2:
        return "Data"
    elif pkt_type == 3:
        return "Extension"
    else:
        return "Could not parse"

def decode_packet_subtype(pkt_type,pkt_subtype):
    return _dot11_subtypes[pkt_type][pkt_subtype]