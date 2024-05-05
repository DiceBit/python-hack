#! usr/bin/env python
import os

import scapy.all as scapy
import requests
import subprocess
import argparse
import datetime as date

NOW = date.datetime.now().strftime("%d-%m-%Y_%H:%M:%S")

def getArg():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="IP", help="[?] Input target IP address")
    parser.add_argument("-f", "--file", dest="File", default=False, action="store_true", help="[?] Redirect output to the file" )
    value = parser.parse_args()

    if os.getuid() != 0:
        print("Use superuser mode")
        exit()

    if not value.IP:
        print("[-] Error: Input IP addr")
        exit()

    if value.File:
        os.chdir("/home/kali/PycharmProjects/Network_Scanner")
        subprocess.call(f"sudo python netscan.py -t {value.IP} > {NOW}.txt", shell=True)
        #subprocess.call(["python", "/home/kali/PycharmProjects/Network_Scanner/netscan.py", f"-t {value.IP}", f"> {NOW}.txt"])

    return value

#obrabotka otveta i vivod informacii
def getInfo(client_list):
    response_OUI = requests.get("https://www.wireshark.org/download/automated/data/manuf")
    content = response_OUI.text


    print(f"Your IP - {IP}")
    print("+----------------+---------------------+-------------------------------------------------+")
    print(f"|  IP            |  MAC                | Vendor")
    print("+----------------+---------------------+-------------------------------------------------+")
    for el in client_list:
        template_mac = (":".join((str(el['mac']).split(":"))[:3]))
        mac_vendor = subprocess.run(["grep", "-i", f"{template_mac}"],
                                    input=content, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout.split("\t")
        ip = el["ip"]
        mac = el["mac"]
        if len(mac_vendor) < 2:
            print(f"|  {ip}  |  {mac}  | ???")
        else:
            print(f"|  {ip}  |  {mac}  | {mac_vendor[1]} - {mac_vendor[2].splitlines()[0]}")
    print("+----------------+---------------------+-------------------------------------------------+")

#formirovanie i otparka arp packetov, poluchenie otveta
def Scanner(ip):
    print("Wait...")
    arp_request = scapy.ARP(pdst=ip)
    ether_broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast_request = ether_broadcast/arp_request
    response_packets_list = scapy.srp(arp_broadcast_request, timeout=1, verbose=False)[0]

    client_list = []
    for el in response_packets_list:
        client = {"ip": el[1].psrc, "mac": el[1].hwsrc}
        client_list.append(client)

    '''
     print(arp_broadcast_request.summary())
     arp_broadcast_request.show()
     scapy.ls(scapy.ARP())
    '''
    return client_list


if __name__ == '__main__':

    IP = getArg().IP
    getInfo(Scanner(IP))
