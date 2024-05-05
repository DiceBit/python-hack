#! /usr/bin/env python

import subprocess
import netfilterqueue
import argparse
import scapy.all as scapy

def getArg():
    parser = argparse.ArgumentParser()
    parser.add_argument("-q", "--queue-number", type=int, required=True, dest="queueNumber", metavar="",
                        help="[?] Input number of queue")
    return parser.parse_args()


def packetProces(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    print(scapy_packet.show())
    packet.accept()
    #packet.drop()


def netCut():
    # subprocess.call([f"iptables -I OUTPUT -j NFQUEUE --queue-num {getArg().queueNumber}"])  # for my obj(self-test)
    # subprocess.call([f"iptables -I INPUT -j NFQUEUE --queue-num {getArg().queueNumber}"])  # for my obj(self-test)
    # subprocess.call([f"iptables -I FORWARD -j NFQUEUE --queue-num {getArg().queueNumber}"]) # for other obj

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



