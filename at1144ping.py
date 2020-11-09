""""Program Description."""

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

# local


# ============================================================== #
#  SECTION: Global Definitions                                   #
# ============================================================== #

PORT = 33439

# ip address of this router
IP_ADDRESS = socket.gethostbyname_ex(socket.gethostname())[-1][-1]

rx_queue = []

# ============================================================== #
#  SECTION: Helpers Static                                       #
# ============================================================== #


class Statistics:
    def __init__(self):
        # used to restrict read/write access to one thread at a time
        self.lock = threading.Lock()
        self.ip_to_stats = dict()

    def create_stat(self, ip):
        self.ip_to_stats[ip] = {'sent': 0,
                                'received': 0,
                                'lost': 0}


class Config:
    def __init__(self, remaining):
        self.stop_threads = False
        self.sequence_number = [0x00, 0x00]
        self.count = remaining
        self.icmp_message = None


class EthernetFrame:
    def __init__(self, destination, source, p_type):
        self.destination = destination,
        self.source = source,
        self.p_type = p_type

    def encode(self):
        return self.destination[0] + self.source[0] + self.p_type

    def __str__(self):
        """To string method for ICMPMessage class."""
        return '==========================\n' \
               'destination: {}\n' \
               'source: {}\n' \
               'type: {}\n' \
               '==========================\n'.format(self.destination[0],
                                                     self.source[0],
                                                     self.p_type)


class IPv4Header:
    def __init__(self, version_header, dsc_ecn, total_length, identification, flags, ttl,
                 protocol, header_checksum, source, destination):
        self.version_header = version_header
        self.dsc_ecn = dsc_ecn
        self.total_length = total_length
        self.identification = identification
        self.flags = flags
        self.ttl = ttl
        self.protocol = protocol
        self.header_checksum = header_checksum
        self.source = source
        self.destination = destination

    def encode(self):
        return self.version_header + self.dsc_ecn + self.total_length + self.identification + \
            self.flags + self.ttl + self.protocol + self.header_checksum + self.source + self.destination

    def __str__(self):
        """To string method for IPv4Header class."""
        return '==========================\n' \
               'version_header: {}\n' \
               'dsc_ecn: {}\n' \
               'total_length: {}\n' \
               'identification: {}\n' \
               'flags: {}\n' \
               'ttl: {}\n' \
               'protocol: {}\n' \
               'header_checksum: {}\n' \
               'source: {}\n' \
               'destination: {}\n' \
               '==========================\n'.format(self.version_header,
                                                     self.dsc_ecn,
                                                     self.total_length,
                                                     self.identification,
                                                     self.flags,
                                                     self.ttl,
                                                     self.protocol,
                                                     self.header_checksum,
                                                     self.source,
                                                     self.destination)


class ICMPMessage:

    def __init__(self, p_type, code, checksum, identifier, sequence_number, data):
        self.p_type = p_type,
        self.code = code,
        self.checksum = checksum,
        self.identifier = identifier,
        self.sequence_number = sequence_number,
        self.data = data

    def encode(self):
        return self.p_type[0] + self.code[0] + self.checksum[0] + self.identifier[0] + \
            self.sequence_number[0] + self.data

    def define_checksum(self):
        start_i = 2
        end_i = 4
        byte_list = list(self.encode())
        checksum = [byte_list[0], byte_list[1]]
        while True:
            if start_i >= len(byte_list):
                break
            if end_i > len(byte_list):
                end_i = len(byte_list)
            segment = byte_list[start_i:end_i]
            remainder = 0
            for i in range(end_i - start_i - 1, -1, -1):
                checksum[i] += remainder
                remainder = 0
                total = checksum[i] + segment[i]
                if total > 0xFF:
                    remainder = 1
                checksum[i] = total & 0xFF
            if end_i - start_i - 1 == 0 and remainder:
                checksum[0] += remainder
                if checksum[0] % 0xFF:
                    remainder = 1
            if remainder:
                if checksum[-1] < 255:
                    checksum[-1] += remainder
                elif checksum[-2] < 255:
                    checksum[-2] += remainder

            start_i = end_i
            end_i += 2

        checksum[0] = checksum[0] ^ 0xFF
        checksum[1] = checksum[1] ^ 0xFF
        self.checksum = (bytes(checksum),)

    def __str__(self):
        """To string method for ICMPMessage class."""
        return '==========================\n' \
               'p_type: {}\n' \
               'code: {}\n' \
               'checksum: {}\n' \
               'identifier: {}\n' \
               'sequence_number: {}\n' \
               'data: {}\n' \
               '==========================\n'.format(self.p_type,
                                                     self.code,
                                                     self.checksum,
                                                     self.identifier,
                                                     self.sequence_number,
                                                     self.data)


# ============================================================== #
#  SECTION: Classes                                              #
# ============================================================== #
def kill_threads(config):
    config.stop_threads = True


def convert_bytes_to_int(byte_list):
    if isinstance(byte_list[0], str):
        new_l = []
        for x in byte_list:
            new_l.append(int('0x{}'.format(x), base=16))
        byte_list = new_l

    return ((byte_list[0] << 8) + byte_list[1]) & 0xFFFF


def ping_timeout(ip, sequence_number, config):
    statistics.lock.acquire()
    try:
        statistics.ip_to_stats[ip]['lost'] += 1
        print('Request timed out.', flush=True)
        config.count -= 1
    finally:
        # relinquish statistics
        statistics.lock.release()


def reader(receiver_socket, config):
    """Utilized by rx thread to parse received messages and insert them into the rx_queue.
       s :socket: socket
       server_address :str: ip of router
    """
    # continue until main thread calls to terminate
    while not config.stop_threads and config.count:
        # if s1 is closed and timedout
        try:
            message, address = receiver_socket.recvfrom(33434)
            if not config.stop_threads:
                hex_value = binascii.hexlify(message).decode()
                hex_value = [hex_value[i:i + 2] for i in range(0, len(hex_value), 2)]

                # indicates ICMP of either reply of response - FIX
                if hex_value[9] == '01' and hex_value[20] == '00':
                    statistics.lock.acquire()
                    try:
                        statistics.ip_to_stats[address[0]][convert_bytes_to_int(hex_value[26:28])]['timer'].cancel()
                        statistics.ip_to_stats[address[0]][convert_bytes_to_int(hex_value[26:28])]['reply_time'] = int(
                            round(time() * 1000))
                        statistics.ip_to_stats[address[0]]['received'] += 1
                    finally:
                        # relinquish statistics
                        statistics.lock.release()

                    print('Reply from {}: bytes={} time={}ms TTL={}'.format(address[0],
                                                                          len(hex_value) - 28,
                                                                          statistics.ip_to_stats[address[0]][convert_bytes_to_int(hex_value[26:28])]['reply_time'] - statistics.ip_to_stats[address[0]][convert_bytes_to_int(hex_value[26:28])]['request_time'],
                                                                          hex_value[8]), flush=True)
                    config.count -= 1
        except:
            break


def sender(sender_socket, count, wait_period):
    print('\nPinging [{}] {} with {} bytes of data:'.format(HOST_NAME, DESTINATION, args.s), flush=True)
    while count and not config.stop_threads:
        # encoded message
        data = []
        for i in range(args.s):
            i = i % 0xFF
            data.append(i)
        icmp_protocol = ICMPMessage(p_type=bytes([0x08]),
                                    code=bytes([0x00]),
                                    checksum=bytes([0x00, 0x00]),
                                    identifier=bytes([(os.getpid() >> 8) & 0xFF,
                                                      os.getpid() & 0xFF]),
                                    sequence_number=bytes(config.sequence_number),
                                    data=bytes(data))

        icmp_protocol.define_checksum()

        encoded_message = icmp_protocol.encode()

        sleep(wait_period)
        if not config.stop_threads:
            # reserve routing table
            statistics.lock.acquire()
            try:
                if DESTINATION not in statistics.ip_to_stats:
                    statistics.create_stat(DESTINATION)

                sender_socket.sendto(encoded_message, (DESTINATION, 33434))

                # statistic
                statistics.ip_to_stats[DESTINATION]['sent'] += 1
                lost_timer = threading.Timer(5, ping_timeout, args=(DESTINATION, config.sequence_number, config))
                lost_timer.start()
                statistics.ip_to_stats[DESTINATION][convert_bytes_to_int(config.sequence_number)] = {'timer': lost_timer,
                                                                                                     'request_time': int(round(time() * 1000)),
                                                                                                     'reply_time': None}

                lb = config.sequence_number[0]
                rb = config.sequence_number[1] + 1
                if rb > 0xFF:
                    rb = 0
                    lb = config.sequence_number[0] + 1
                    if lb > 0xFF:
                        lb = 0
                config.sequence_number = [lb, rb]

                count -= 1
            finally:
                # relinquish statistics
                statistics.lock.release()
# ============================================================== #
#  SECTION: Main                                                 #
# ============================================================== #


if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('-c', default=-1, type=int, required=False,
                        help='Stop after sending (and receiving) count ECHO_RESPONSE packets.  '
                             'If this option is not specified, ping will operate until interrupted.')
    parser.add_argument('-i', default=1, type=int, required=False,
                        help='Number of seconds between sending each packet.'
                             'The default is to wait for one second between each packet.')
    parser.add_argument('-s', default=56, type=int, required=False,
                        help='The number of data bytes to be sent')
    parser.add_argument('-t', default=10, type=int, required=False,
                        help='Seconds before ping exits regardless of how many packets have been received')
    parser.add_argument('ip', type=str, help='Ip to ping')
    args = parser.parse_args()

    HOST_NAME = args.ip
    DESTINATION = HOST_NAME

    if args.ip.count('.') != 4:
        DESTINATION = socket.gethostbyname(HOST_NAME)

    # receiver socket setup
    s1 = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname('icmp'))
    s1.bind((IP_ADDRESS, 0))

    s1.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    config = Config(args.c)
    timeout_timer = threading.Timer(args.t, kill_threads, args=(config,))
    timeout_timer.start()

    statistics = Statistics()

    # # create transmit thread
    tx = threading.Thread(target=sender, args=(s1, args.c, args.i))
    tx.start()

    # create receive thread
    rx = threading.Thread(target=reader, args=(s1, config))
    rx.start()

    tx.join()
    while config.count and not config.stop_threads:
        sleep(1)

    icmp_protocol = ICMPMessage(p_type=bytes([0x08]),
                                code=bytes([0x00]),
                                checksum=bytes([0x00, 0x00]),
                                identifier=bytes([(os.getpid() >> 8) & 0xFF,
                                                  os.getpid() & 0xFF]),
                                sequence_number=bytes(config.sequence_number),
                                data=bytes([0x00, 0x00]))

    icmp_protocol.define_checksum()

    encoded_message = icmp_protocol.encode()
    s1.close()
    rx.join()
    timeout_timer.cancel()

    rtt_times = []
    total_time = 0
    for ip, value in list(statistics.ip_to_stats.items()):
        print('\nPing statistics for {} with {} bytes of data:'.format(DESTINATION, args.s))
        print('\tPackets Sent = {}, Received = {}, lost = {} ({} % loss)'.format(value['sent'],
                                                                                 value['received'],
                                                                                 value['sent'] -
                                                                                 value['received'],
                                                                                 int(((value['sent'] -
                                                                                 value['received']) /
                                                                                 value['sent']) * 100)
                                                                                 ))
        highest_sequence = convert_bytes_to_int(config.sequence_number)
        for i in range(highest_sequence):
            value[i]['timer'].cancel()
            if value[i]['reply_time']:
                rtt_times.append(value[i]['reply_time'] - value[i]['request_time'])
                total_time += value[i]['reply_time'] - value[i]['request_time']

    if rtt_times:
        print('Approximate round trip times in milli-seconds')
        print('\tMinimum = {}ms, Maximum = {}ms, Average = {}ms'.format(min(rtt_times),
                                                                        max(rtt_times),
                                                                        total_time / len(rtt_times)))
