# IP Address Finder Utility

## Description

The IP Address Finder Utility is the utility designed to find the IP adress range your device belongs to if you are unsure and/or didn't give you the valid IP configuration.

The approach is to assign a random IP address within the specified range for your specified interface and try to ping the boundary addresses where the gateway is being usually located. It's still work in progress however it might be useful if you forget your IP address configuration or you have some piece of equipment that you don't forgot all the configuration.

Please note that is causes a lot of network pollution using ICMP ECHO (ping) requests. 

## Disclaimer

This utility has been designed to find IP address of your own network devices you forget IP configuration of. It has not been designed to promote any illegal activity.

Do NOT use it for any reconnaissance or similiar potencially illegal activity as any IDS/IPS systems might block you and you might be reported/persecuted for some organization policy violation if used within organization environment.

## Usage

Syntax:
```
IP Address Finder Utility

options:
  -h, --help            show this help message and exit
  --interface INTERFACE
                        Name of the network interface to use.
  --ip-range IP_RANGE   Comma-separated list of IP address ranges in CIDR format, defaults to "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
  --boundary-width BOUNDARY_WIDTH
                        Set the address boundary width, defaults to 1 for the first (one from the beginning) and last (one from the end) IP address
  --sleep-time SLEEP_TIME
                        Sleep time in milliseconds between IP address changes and pings, 0 to disable sleep, default is 1000
  --ping-confirmations PING_CONFIRMATIONS
                        Number of required ICMP ping confirmations, defaults 8
  --timeout TIMEOUT     Ping timeout, defaults to 1
  --debug               Enable debug mode.
```

Example:

```
./ping.py --interface enp9s0 --ip-range 192.168.0.0/16
```

The example uses enp9s0 interface and it tries the discovery of relevant and accessible subnet in the 192.168.0.0/16 range.

