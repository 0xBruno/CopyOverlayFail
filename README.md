# CopyOverlayFail
CopyFail for cross-container code execution

This lab tests whether CVE-2026-31431 / CopyFail can be used for cross-container code execution when two containers share the same overlay2 lower-layer inode for an executable.

- both containers use the same local base image;
- attacker poisons the page cache for `/usr/bin/whoami`;
- victim executes `/usr/bin/whoami`;
- attacker code executes inside the victim namespace.
