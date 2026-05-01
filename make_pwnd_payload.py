#!/usr/bin/env python3
import argparse


def build_payload(message=b"PWND\n"):
    message_offset_from_lea_end = 0x10
    shellcode = bytes.fromhex(
        # mov eax, SYS_write
        "b801000000"
        # mov edi, STDOUT_FILENO
        "bf01000000"
        # lea rsi, [rip+0x10]
        "488d35"
    ) + message_offset_from_lea_end.to_bytes(4, "little") + bytes.fromhex(
        # mov edx, len(message)
        "ba"
    ) + len(message).to_bytes(4, "little") + bytes.fromhex(
        # syscall
        "0f05"
        # xor edi, edi
        "31ff"
        # mov eax, SYS_exit
        "b83c000000"
        # syscall
        "0f05"
    ) + message

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


def main():
    parser = argparse.ArgumentParser(description="Build a tiny x86-64 ELF that prints PWND.")
    parser.add_argument("output", nargs="?", default="payload_pwnd.elf")
    args = parser.parse_args()

    payload = build_payload()
    with open(args.output, "wb") as output:
        output.write(payload)
    print(f"wrote {len(payload)} bytes to {args.output}")


if __name__ == "__main__":
    main()
