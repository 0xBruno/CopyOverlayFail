# Notebook Runtime Lab

Minimal Jupyter-image variant of CopyOverlayFail.

Both containers use `quay.io/jupyter/base-notebook`. The attacker poisons the shared Conda `pip` executable. The victim later runs `pip`, simulating a common notebook package-management action, and executes an in-memory ELF payload generated from a pasted notebook cell.

This is not a new vulnerability and not host escape. It reuses the original CopyFail primitive against a shared notebook image-layer file.

## Run

```bash
docker compose up -d
```

Open both notebooks:

```text
attacker: http://127.0.0.1:8888/?token=attacker
victim:   http://127.0.0.1:9999/?token=victim
```

In the victim notebook, open a Terminal and baseline `pip`:

```bash
/opt/conda/bin/pip --version
```

Expected: normal `pip` version output.

In the attacker notebook, create a Python notebook and paste the full contents of `sploit.py` into one cell. Run the cell.

The last line is `run()`, which poisons `/opt/conda/bin/pip` with an in-memory payload that prints `PWND`.

Expected:

```text
[+] target: /opt/conda/bin/pip
[+] in-memory print payload: 'PWND'
[+] payload length: 160 bytes
[+] wrote 160 bytes through AF_ALG/splice page-cache primitive
```

Back in the victim Terminal, run `pip` again:

```bash
/opt/conda/bin/pip --version
```

Expected:

```text
PWND
```

That final command represents a future notebook action that execs a shared image-layer tool. Already-running processes are not affected; the trigger is the next `execve()` of the poisoned inode.

## Cleanup

```bash
docker compose down --remove-orphans
sudo sync
sudo sh -c 'echo 3 > /proc/sys/vm/drop_caches'
```

Use a disposable VM. This can poison cached executable pages for the local Jupyter image.
