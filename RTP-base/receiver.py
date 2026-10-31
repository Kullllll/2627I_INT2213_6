import argparse
from email.mime import message
import socket
import os
import sys

from utils import PacketHeader, compute_checksum

START, END, DATA, ACK = 0, 1, 2, 3
HEADER_SIZE, MAX_PACKET_SIZE = 16, 1472
SELECTIVE_ACK = False

def log(message):
    if os.environ.get("RTP_DEBUG") == "1":
        print(message, file=sys.stderr, flush=True)

def make_ack(seq):
    header = PacketHeader(type=ACK, seq_num=seq, length=0, checksum=0)
    header.checksum = compute_checksum(header)
    return bytes(header)


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


def receiver(receiver_ip, receiver_port, window_size):
    peer = None
    expected_seq = 1
    recv_buffer = {}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((receiver_ip, receiver_port))
        log("LISTENING")
        while True:
            raw, address = sock.recvfrom(65535)
            packet = parse_packet(raw)
            if packet is None:
                log("DROP malformed/corrupted packet")
                continue
            kind, seq, payload = packet
            if peer is None:
                if kind == START and seq == 0:
                    peer = address
                    sock.sendto(make_ack(1), peer)
                    log("RECV START; SEND ACK=1")
                continue
            if address != peer or kind == START:
                continue
            if kind == END:
                if seq == expected_seq:
                    sys.stdout.buffer.flush()
                    sock.sendto(make_ack(seq + 1), peer)
                    log(f"RECV END seq={seq}; exit")
                    return
                continue
            if kind != DATA or seq < 1:
                continue

            if seq >= expected_seq + window_size:
                if not SELECTIVE_ACK:
                    sock.sendto(make_ack(expected_seq), peer)
                continue
            if seq >= expected_seq:
                recv_buffer.setdefault(seq, payload)
            while expected_seq in recv_buffer:
                sys.stdout.buffer.write(recv_buffer.pop(expected_seq))
                expected_seq += 1
            sys.stdout.buffer.flush()
            ack = seq if SELECTIVE_ACK else expected_seq
            sock.sendto(make_ack(ack), peer)
            log(f"RECV DATA seq={seq}; SEND ACK={ack}; expected={expected_seq}")



def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("receiver_ip")
    parser.add_argument("receiver_port", type=int)
    parser.add_argument("window_size", type=int)
    args = parser.parse_args()
    if not 1 <= args.receiver_port <= 65535 or args.window_size < 1:
        parser.error("port phai tu 1..65535; window_size phai >= 1")
    receiver(args.receiver_ip, args.receiver_port, args.window_size)


if __name__ == "__main__":
    main()
