#! /usr/bin/env python

import argparse
import subprocess, os
import netfilterqueue
import scapy.all as scapy
import zlib
from scapy.layers import http

def getArg():
    parser = argparse.ArgumentParser()
    parser.add_argument("-q", "--queue-number", type=int, required=True, dest="queueNumber", metavar="",
                        help="[?] Number of queue")
    return parser.parse_args()


def packetProccess(packet):
    scapy_packet = scapy.IP(packet.get_payload())

    if scapy_packet.haslayer(http.HTTP): #or scapy_packet.haslayer(scapy.Raw) or scapy_packet.haslayer(http.Raw)
        print(scapy_packet.show())
        print(scapy_packet[http.HTTP])
        try:
            data = scapy_packet[scapy.Raw].load
            print(f"data: {data}")
            print(zlib.decompress(data))
        except:
            print("")
        '''
        if scapy_packet.haslayer(scapy.TCP):

            if (scapy_packet.haslayer(http.HTTPRequest)
                    or scapy_packet[scapy.TCP].dport == 80
                    or scapy_packet[scapy.TCP].dport == 443):
                print("\nRequest\n")
                print(scapy_packet.show())

            elif (scapy_packet.haslayer(http.HTTPResponse)
                    or scapy_packet[scapy.TCP].sport == 80
                    or scapy_packet[scapy.TCP].sport == 443):
                print("\nResponse\n")
                print(scapy_packet.show())

        elif scapy_packet.haslayer(scapy.UDP):

            if (scapy_packet.haslayer(http.HTTPRequest)
                    or scapy_packet[scapy.UDP].dport == 80
                    or scapy_packet[scapy.UDP].dport == 443):
                print("\nRequest\n")
                print(scapy_packet.show())

            elif (scapy_packet.haslayer(http.HTTPResponse)
                    or scapy_packet[scapy.UDP].sport == 80
                    or scapy_packet[scapy.UDP].sport == 443):
                print("\nResponse\n")
                print(scapy_packet.show())

        else:
            print("---------NOTHING--------")
            print(scapy_packet.show())
        '''
    #packet.set_payload(bytes(scapy_packet))
    packet.accept()


def fileSnif():
    if os.getuid() != 0:
        print("Use super user mod")
        exit()

    subprocess.call(["iptables", "-I", "OUTPUT", "-j", "NFQUEUE", "--queue-num", f"{getArg().queueNumber}"])
    subprocess.call(["iptables", "-I", "INPUT", "-j", "NFQUEUE", "--queue-num", f"{getArg().queueNumber}"])

    queue = netfilterqueue.NetfilterQueue()
    queue.bind(getArg().queueNumber, packetProccess)
    queue.run()

if __name__ == '__main__':
    try:
        fileSnif()
    except KeyboardInterrupt:
        subprocess.call(["iptables", "--flush"])
        print("\nDetected ctrl + C")
        exit()


