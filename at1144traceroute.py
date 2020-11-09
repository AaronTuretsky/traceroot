# ============================================================== #
#  SECTION: Imports                                              #
# ============================================================== #

# standard library
import argparse
import threading
import os
import binascii
import sys
from time import sleep, time
# third party library
import socket
import struct

# local

IP_ADDRESS = socket.gethostbyname_ex(socket.gethostname())[-1][-1]
PORT = 33521


def create_sender(ttl):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
    return s


def create_reciever(timeout=1000):
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    s.bind(('', PORT))
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, timeout)
    return s

# ============================================================== #
#  SECTION: Main                                                 #
# ============================================================== #


if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('-n', action='store_true',
                        help='Print hop addresses numerically rather than symbolically and numerically.')
    parser.add_argument('-q', default=1, type=int, required=False,
                        help='Set the number of probes per ``ttl'' to nqueries.')
    parser.add_argument('-S', action='store_true',
                        help='Print a summary of how many probes were not answered for each hop.')
    parser.add_argument('ip', type=str, help='Ip to ping')
    args = parser.parse_args()

    host_name = args.ip
    destination = host_name
    if args.ip.count('.') != 4:
        destination = socket.gethostbyname(host_name)
    print(destination)
    print(IP_ADDRESS)

    ttl = 30
    hops = 30
    address = None
    while ttl <= hops and address != destination:
        rx_s = create_reciever()
        tx_s = create_sender(ttl)

        tx_time = int(round(time() * 1000))
        tx_s.sendto(b'', (destination, PORT))

        rec_info = None
        rx_time = None
        try:
            message, rec_info = rx_s.recvfrom(1024)
            address = rec_info[0]
            rx_time = int(round(time() * 1000))
        except socket.error as e:
            print(e)
            pass
        finally:
            tx_s.close()
            rx_s.close()

        if rec_info:
            rtt = rx_time - tx_time
            print('{} {} {}ms'.format(ttl, address, rtt))
        else:
            print('{} *'.format(ttl))

        ttl += 1
