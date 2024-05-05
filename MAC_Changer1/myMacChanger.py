#! usr/bin/env python
import random
import string
import subprocess
import optparse
import re
import os

def randomMac():
    def generateRandomMac():
        rm = ""
        parts = [''.join(random.choices(string.hexdigits, k=2)) + ':' for _ in range(5)]
        lastPart = ''.join(random.choices(string.hexdigits, k=2))
        for p in parts:
            rm += p
        for q in lastPart:
            rm += q
        return rm

    random_string = generateRandomMac()
    while not re.fullmatch(r'(\w\w:){5}\w{2}', random_string):
        random_string = generateRandomMac()
    return random_string.lower()

def getMyMac(targetInterface):
    output = subprocess.check_output(["ifconfig", targetInterface])
    searchMac = re.search(r'(\w\w:){5}(\w{2})', str(output))
    return searchMac.group(0)

def chechChange(targetInterface, wantedMac):

    if getMyMac(targetInterface) == wantedMac:
        print("[+] Mac successfully changed")
        exit()

    else:
        print("[-] Error sm went wrong")
        val = input("[?] Want try another? [Y/n] ")
        match val.lower().split():
            case ["y"]:
                macChanger(targetInterface, randomMac())
            case ["n"]:
                print(f"[?] Your mac is {getMyMac(targetInterface)}")
                exit()
            case _:
                print(f"[?] Your mac is {getMyMac(targetInterface)}")
                exit()

def macChanger(targetInterface, wantedMac):

    if os.getuid() != 0:
        print("[-] Error. Please use superuser mode")
        exit()

    print(f"[+] Changing {targetInterface} MAC-address to {wantedMac}")

    subprocess.call(["ifconfig", targetInterface, "down"])
    subprocess.call(["ifconfig", targetInterface, "hw", "ether", wantedMac])
    subprocess.call(["ifconfig", targetInterface, "up"])

    chechChange(targetInterface, wantedMac)

def start():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="targetInterface", help="[?] Input target interface")
    parser.add_option("-m", "--mac", dest="wantedMac", help="[?] Input wanted MAC")
    parser.add_option("-r", "--random", dest="randomMac", default=False, action="store_true", help="[?] Generate random MAC")
    parser.add_option("-g", "--get-mac", dest="getMac", default=False, action="store_true", help="[?] Print your MAC")
    (values, argument) = parser.parse_args()

    if values.targetInterface and values.getMac:
        print(getMyMac(values.targetInterface))
        exit()

    if not values.targetInterface:
        print("[-] Error. Input interface arg, use --help for details")
        exit()
    if values.wantedMac and values.randomMac:
        print("[-] Error. Please use -m <value> OR -r")
        exit()
    if not values.wantedMac and not values.randomMac:
        print("[-] Error. Input mac arg, use --help for details")
        exit()

    if values.targetInterface and values.wantedMac:
        macChanger(values.targetInterface, values.wantedMac)
        exit()
    if values.targetInterface and values.randomMac:
        macChanger(values.targetInterface, randomMac())
    else:
        print("[-] Error sm went wrong")
        exit()



if __name__ == '__main__':
    start()

