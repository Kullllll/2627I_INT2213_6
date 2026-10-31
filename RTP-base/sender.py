import argparse
import os
import socket
import sys
import time

from utils import PacketHeader, compute_checksum

START, END, DATA, ACK = 0, 1, 2, 3
HEADER_SIZE, MAX_PACKET_SIZE = 16, 1472
MAX_PAYLOAD_SIZE = MAX_PACKET_SIZE - HEADER_SIZE
TIMEOUT = 0.5
SELECTIVE_ACK = False  


def log(message):
    if os.environ.get("RTP_DEBUG") == "1":
        print(message, file=sys.stderr, flush=True)


def make_packet(kind, seq, payload=b""):
    header = PacketHeader(type=kind, seq_num=seq, length=len(payload), checksum=0)
    header.checksum = compute_checksum(header / payload)
    return bytes(header / payload)


def parse_packet(raw):
    if not HEADER_SIZE <= len(raw) <= MAX_PACKET_SIZE:
        return None
    header = PacketHeader(raw[:HEADER_SIZE])
    if header.type not in (START, END, DATA, ACK):
        return None
    if header.length != len(raw) - HEADER_SIZE:
        return None
    if header.type != DATA and header.length != 0:
        return None
    cleared = raw[:12] + b"\x00" * 4 + raw[16:]
    if header.checksum != compute_checksum(cleared):
        return None
    return int(header.type), int(header.seq_num), raw[HEADER_SIZE:]


def receive_ack(sock, peer):
    raw, address = sock.recvfrom(65535)
    if address != peer:
        return None
    packet = parse_packet(raw)
    if packet is None or packet[0] != ACK:
        return None
    return packet[1]


def sender(receiver_ip, receiver_port, window_size):
    peer = (socket.gethostbyname(receiver_ip), receiver_port)
    message = sys.stdin.buffer.read()
    packets = [make_packet(DATA, i // MAX_PAYLOAD_SIZE + 1,
                           message[i:i + MAX_PAYLOAD_SIZE])
               for i in range(0, len(message), MAX_PAYLOAD_SIZE)]
    total = len(packets)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(make_packet(START, 0), peer)
        log("SEND START seq=0; wait ACK=1")
        while receive_ack(sock, peer) != 1:
            pass

        base, next_seq = 1, 1
        acknowledged = set()
        timer_start = None
        while base <= total:
            while next_seq <= total and next_seq < base + window_size:
                sock.sendto(packets[next_seq - 1], peer)
                log(f"SEND DATA seq={next_seq}")
                next_seq += 1
                if timer_start is None:
                    timer_start = time.monotonic()

            remaining = TIMEOUT - (time.monotonic() - timer_start)
            if remaining <= 0:
                for seq in range(base, next_seq):
                    if not SELECTIVE_ACK or seq not in acknowledged:
                        sock.sendto(packets[seq - 1], peer)
                        log(f"RETRANSMIT DATA seq={seq}")
                timer_start = time.monotonic()
                continue

            sock.settimeout(remaining)
            try:
                ack = receive_ack(sock, peer)
            except socket.timeout:
                continue
            if ack is None:
                continue
            previous_base = base
            if SELECTIVE_ACK:
                if base <= ack < next_seq:
                    acknowledged.add(ack)
                    while base in acknowledged:
                        acknowledged.remove(base)
                        base += 1
            elif base < ack <= next_seq:
                base = ack
            if base > previous_base:
                log(f"ACK={ack}; base={base}; next_seq={next_seq}")
                timer_start = time.monotonic()

        end_seq = total + 1
        sock.sendto(make_packet(END, end_seq), peer)
        log(f"SEND END seq={end_seq}")
        deadline = time.monotonic() + TIMEOUT
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                if receive_ack(sock, peer) == end_seq + 1:
                    break
            except socket.timeout:
                break


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("receiver_ip")
    parser.add_argument("receiver_port", type=int)
    parser.add_argument("window_size", type=int)
    args = parser.parse_args()
    if not 1 <= args.receiver_port <= 65535 or args.window_size < 1:
        parser.error("port phai tu 1..65535; window_size phai >= 1")
    sender(args.receiver_ip, args.receiver_port, args.window_size)


if __name__ == "__main__":
    main()