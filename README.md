# CopyOverlayFail

CopyFail reuse labs for shared page-cache trust-boundary testing.

This repository does not claim a new vulnerability. It reuses the original CopyFail primitive in environments where separate workloads can reference the same underlying inode/page-cache object.

Labs:

- `containers-lab/`: two Ubuntu containers sharing the same image-layer executable.
- `notebook-lab/`: two Jupyter notebook-image containers sharing `/opt/conda/bin/python`.

Shared tooling:

- `sploit.py`: generic CopyFail page-cache injector: `sploit.py <target-filepath> <payload-elf>`.
- `make_pwnd_payload.py`: builds `payload.elf`, a tiny ELF that prints `PWND`.
