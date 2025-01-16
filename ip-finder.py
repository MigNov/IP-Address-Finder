#!/usr/bin/env python3
import os
import sys
import fcntl
import ctypes
import socket
import struct
import time
import select
import random
import argparse
import ipaddress

ADDRESS_RANGES = '10.0.0.0/8,172.16.0.0/12,192.168.0.0/16'

ICMP_ECHO_REQUEST = 8
SIOCSIFADDR = 0x8916     # Set the IP address
SIOCSIFNETMASK = 0x891C  # Set the netmask

DEBUG = False
DEFAULT_CONFIRMATIONS = 8

def debug_print(msg):
    '''
    Show the debug print message if appropriate

    Args:
        msg (str): string to print

    Stderr output:
        message string prefixed by [DEBUG] prefix
    '''
    if not DEBUG:
        return
    print(f'[DEBUG] {msg}', file=sys.stderr)

def time_in_seconds():
    '''
    Get time in seconds

    Returns:
        int: returns UNIX timestamp
    '''
    return int(str(time.time()).split('.')[0])

def checksum(source_string):
    '''
    Calculate packet checksum of the supplied data

    Args:
        source_string (str): packet data to use for calculations

    Returns:
        bytes: checksum
    '''
    sum = 0
    count_to = (len(source_string) // 2) * 2
    count = 0
    while count < count_to:
        this = source_string[count + 1] * 256 + source_string[count]
        sum = sum + this
        sum = sum & 0xFFFFFFFF
        count = count + 2
    if count_to < len(source_string):
        sum = sum + source_string[-1]
        sum = sum & 0xFFFFFFFF
    sum = (sum >> 16) + (sum & 0xFFFF)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xFFFF
    answer = answer >> 8 | (answer << 8 & 0xFF00)
    return answer

def create_packet(id):
    '''
    Create a new echo request packet based on the given id

    Args:
        id (int): packet ID for ICMP_ECHO_REQUEST creation

    Returns:
        bytes: packet data
    '''
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, 0, id, 1)
    data = struct.pack("d", time.time())
    cs = checksum(header + data)
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(cs), id, 1)
    return header + data

def ping_once(dest_addr, interface_name = None, timeout = 1):
    '''
    Send a ping to the given destination address and return the delay

    Args:
        dest_addr (str): destination address to ping
        interface_name (str): interface name to use for pinging
        timeout (int): timeout for ping in seconds

    Returns:
        None on error
        float: delay in seconds 
    '''
    try:
        # Resolve the host address
        dest_addr = socket.gethostbyname(dest_addr)
    except socket.gaierror:
        return None

    icmp = socket.getprotobyname('icmp')
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)

    # Bind to interface_name if appropriate
    if interface_name:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface_name.encode())

    packet_id = (os.getpid() + random.randrange(0, 100)) & 0xFFFF
    packet = create_packet(packet_id)
    sock.sendto(packet, (dest_addr, 1))
    start_time = time.time()

    while True:
        started_select = time.time()
        what_ready = select.select([sock], [], [], timeout)
        how_long_in_select = time.time() - started_select
        if what_ready[0] == []:  # Timeout
            return None

        time_received = time.time()
        rec_packet, addr = sock.recvfrom(1024)
        icmp_header = rec_packet[20:28]
        type, code, checksum, p_id, sequence = struct.unpack('bbHHh', icmp_header)
        if p_id == packet_id:
            time_sent = struct.unpack('d', rec_packet[28:28 + struct.calcsize("d")])[0]
            debug_print(f'Ping reply from {dest_addr} received.')
            return time_received - time_sent

        timeout = timeout - how_long_in_select
        if timeout <= 0:
            return None

def ping(dest_addr, interface_name = None, timeout = 1, required_confirmations = 4, sleep_time = 0):
    '''
    Ping destination address using specified interface

    Args:
        dest_addr (str): destination address to ping
        interface_name (str): interface to use for ping
        timeout (int): ping timeout in seconds
        required_confirmations (int): number of confirmation packets required
        sleep_time (int): time to sleep between tries in milliseconds

    Returns:
        bool: True if all the pings passed, False otherwise
    '''
    try:
        debug_print(f'Trying ping to {dest_addr} ...')
        if not ping_once(dest_addr, interface_name, timeout):
            debug_print(f'Ping to {dest_addr} failed')
            return False

        num = 1
        while num < required_confirmations:
            if ping_once(dest_addr, interface_name, timeout):
                if sleep_time and sleep_time > 0:
                    time.sleep(sleep_time / 1000.)
                debug_print(f'Ping #{num} of {dest_addr} passed.')
                num = num + 1
    except:
        return False

    return num == required_confirmations

def get_address(cidr, prefix_len=24):
    '''
    Get IP address specified by CIDR aligned to subnet prefix

    Args:
        cidr (str): CIDR definition
        prefix_len (int): prefix length in bits, defaults to 24

    Returns:
        list: List of subnets aligned to prefix_len
    '''
    ip_range = ipaddress.ip_network(cidr)
    return list(ip_range.subnets(new_prefix=prefix_len))

def get_address_list(addr_range):
    '''
    Get IP addresses list for addr_range

    Args:
        addr_range (str): IP address range

    Returns:
        list: IP address list
    '''
    out = []
    addrs = get_address(addr_range)
    for res in addrs:
        out.append(res)

    return out

def get_boundary_addresses(subnet, boundary_width = 1):
    '''
    Get boundary addreses for subnet

    Args:
        subnet (str): subnet to get addresses for
        boundary_width (int): width of the address boundary

    Returns:
        tuple: (minimum_addresses, maximum_addresses, subnet_mask)
    '''
    ip_range = ipaddress.ip_network(subnet)
    netmask = str(ip_range.netmask)
    addr_list = list(ip_range.subnets(new_prefix=32))
    if len(addr_list) < 2:
        return None
    hostmins = []
    hostmaxs = []
    for i in range(0, boundary_width):
        hostmin = addr_list[1 + i]
        hostmins.append( str(hostmin).replace('/32', '') )
        hostmax = addr_list[ len(addr_list) - 2 - i ] 
        hostmaxs.append( str(hostmax).replace('/32', '') )
    return (hostmins, hostmaxs, netmask)

def get_random_address_in_range(subnet):
    '''
    Get the ranomd IP address in the specified subnet

    Args:
        subnet (str): subnet to get IP address in

    Returns
        str: IP address
    '''
    net = ipaddress.ip_network(subnet)
    random_ip_int = random.randint(int(net.network_address), int(net.broadcast_address))
    return str(ipaddress.IPv4Address(random_ip_int))

def subnet_mask_to_prefix_len(subnet_mask):
    '''
    Convert a dotted-decimal subnet mask to prefix length.
    
    Args:
        subnet_mask (str): Subnet mask in dotted-decimal format (e.g., "255.255.255.0").
    
    Returns:
        int: Prefix length (e.g., 24).
    '''
    # Use ipaddress.IPv4Network with strict=False to interpret the subnet mask
    network = ipaddress.IPv4Network(f'0.0.0.0/{subnet_mask}', strict=False)
    return network.prefixlen

def set_interface_ip(interface_name, ip_address, netmask):
    '''
    Set the IP address and netmask of a network interface.

    Args:
        interface_name (str): The name of the interface (e.g., "eth0").
        ip_address (str): The IP address to set (e.g., "192.168.1.100").
        netmask (str): The subnet mask to set (e.g., "255.255.255.0").

    Returns:
        bool: True on success, False on error
    '''
    ret = False
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Set IP address
        rbytes = socket.inet_aton(ip_address)
        ifreq = struct.pack('16sH2s4s8s', interface_name.encode('utf-8')[:15], socket.AF_INET, b'\x00'*2, rbytes, b'\x00'*8)
        fcntl.ioctl(sock, SIOCSIFADDR, ifreq)

        # Set netmask
        mask_len = subnet_mask_to_prefix_len(netmask)
        mask_len = ctypes.c_uint32(~((2 ** (32 - mask_len)) - 1)).value
        rbytes = socket.htonl(mask_len)
        ifreq = struct.pack('16sH2sI8s', interface_name.encode('utf-8')[:15], socket.AF_INET, b'\x00'*2, rbytes, b'\x00'*8)
        fcntl.ioctl(sock, SIOCSIFNETMASK, ifreq)

        debug_print(f"Successfully set {interface_name} to IP: {ip_address}, Netmask: {netmask}")
        ret = True
    except Exception as e:
        debug_print(f"Failed to set interface {interface_name}: {e}")
    finally:
        sock.close()

    return ret

def progress_bar(percent, length=None, fill="█", empty=" "):
    '''
    Draws a progress bar based on the percentage.

    Args:
        percent (float): Percentage completion (0 to 100).
        length (int): The total length of the progress bar in characters, can be None for autodetection
        fill (str): The character for the filled portion.
        empty (str): The character for the empty portion.
    '''

    if length is None:
        length = int(os.get_terminal_size()[0]) - 10

    # Ensure percentage stays between 0 and 100
    percent = max(0, min(100, percent))

    # Calculate the number of filled characters
    filled_length = int(length * percent / 100)
    bar = fill * filled_length + empty * (length - filled_length)

    # Print the bar with percentage
    sys.stdout.write(f"\r|{bar}| {percent:.1f}%")
    sys.stdout.flush()

if __name__ == "__main__":
    '''
    Main entrypoint
    '''
    parser = argparse.ArgumentParser(description="IP Address Finder Utility")
    parser.add_argument('--interface', type=str, required=True,  help='Name of the network interface to use.')
    parser.add_argument('--ip-range',  type=str, required=False, help=f'Comma-separated list of IP address ranges in CIDR format, defaults to "{ADDRESS_RANGES}"')
    parser.add_argument('--boundary-width', type=int, required=False, help='Set the address boundary width, defaults to 1 for the first (one from the beginning) and last (one from the end) IP address')
    parser.add_argument('--sleep-time',  type=int, required=False, help='Sleep time in milliseconds between IP address changes and pings, 0 to disable sleep, default is 1000')
    parser.add_argument('--ping-confirmations',  type=int, required=False, help=f'Number of required ICMP ping confirmations, defaults {DEFAULT_CONFIRMATIONS}')
    parser.add_argument('--timeout',  type=int, required=False, help='Ping timeout, defaults to 1')
    parser.add_argument('--debug', action="store_true", help='Enable debug mode.')
    args = parser.parse_args()

    DEBUG = args.debug

    address_ranges = ADDRESS_RANGES
    if args.ip_range:
        address_ranges = args.ip_range

    sleep_time = 1000
    if args.sleep_time and args.sleep_time > 0:
        sleep_time = args.sleep_time

    timeout = 1
    if args.timeout:
        timeout = args.timeout

    req_confirmations = DEFAULT_CONFIRMATIONS
    if args.ping_confirmations:
        req_confirmations = args.ping_confirmations

    l = []

    addr_ranges = address_ranges.split(',')

    boundary_width = 1
    if args.boundary_width:
        boundary_width = args.boundary_width

    index = 0
    max_addrs = 0
    for single_range in addr_ranges:
        l = get_address_list(single_range)
        max_addrs += len(l)

    print(f'Discovery running on interface {args.interface} for {max_addrs} subnets')
    time_start = time_in_seconds()
    for single_range in addr_ranges:
        l = get_address_list(single_range)
        for subnet in l:
            index = index + 1
            percent = round((index / max_addrs) * 100, 2)
            time_current = time_in_seconds()
            time_delta = time_current - time_start
            if not DEBUG:
                progress_bar( percent )
            debug_print(f'Processing {index}/{max_addrs} ({percent}% in {time_delta} second(s))')
            boundary = get_boundary_addresses(subnet, boundary_width)
            addr_found = None
            if boundary:
                random_addr = get_random_address_in_range(subnet)
                if not set_interface_ip(args.interface, random_addr, boundary[2]):
                    debug_print(f'Error: Cannot set IP address {random_addr} to interface {args.interface}')
                    continue

                try:
                    if sleep_time and sleep_time > 0:
                        time.sleep( sleep_time / 1000. )

                    found = False
                    for address in boundary[0]:
                        if ping(address, args.interface, timeout, req_confirmations, sleep_time):
                            addr_found = address
                            found = True

                    if not found:
                        for address in boundary[1]:
                            if ping(address, args.interface, timeout, req_confirmations, sleep_time):
                                addr_found = address
                                found = True

                    if not found:
                        continue
                except KeyboardInterrupt:
                    print()
                    print('Interrupted by user')
                    sys.exit(1)

                time_current = time_in_seconds()
                time_delta = time_current - time_start
                debug_print(f'Ping on interface {args.interface} passed. Target IP: {addr_found}, IP Address: {random_addr}, netmask: {boundary[2]}')
                if not DEBUG:
                     progress_bar( 100.0 )
                     print()
                print(f'Found gateway IP address {addr} with netmask {boundary[2]} in {time_delta} second(s)')
                sys.exit(0)
            debug_print(f'{single_range}: {boundary}, random address = {random_addr}')
        debug_print(f'{single_range}: {len(l)} * /24 addresses')

    if not DEBUG:
         progress_bar( 100.0 )
         print()

    print('No IP Address found')
    sys.exit(1)

