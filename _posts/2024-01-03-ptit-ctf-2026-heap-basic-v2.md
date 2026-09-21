---
title: "PTIT CTF 2026 - PWN - Heap_basic_V2"
date: 2024-01-03 00:00:00 +0700
categories: [CTF, Heap Exploitation]
tags: [pwn, heap, uaf, house-of-apple, tcache, libc, ptit-ctf]
author: datious
description: "PTIT CTF 2026 writeup: Heap_basic_V2 — Use-After-Free with House of Apple 2 technique to hijack stdout FILE object on Ubuntu 22.04 libc."
image:
  path: https://hackmd.io/_uploads/HkWdWq2wzl.png
---

# PTIT CTF 2026 - PWN challenge - Heap_basic_V2
**Author: datious**

![Challenge](https://hackmd.io/_uploads/HkWdWq2wzl.png)

## 1. Overview

![Files](https://hackmd.io/_uploads/rJ2bM92DGe.png)

The challenge provides four files:
- `chall` (binary)
- `docker-compose`
- `Dockerfile`
- `entrypoint.sh`

Based on **Dockerfile**, we will get the libc file from **Ubuntu 22.04**.

## 2. Analyzing and Gathering

**Security mitigations:**

![Checksec](https://hackmd.io/_uploads/rkP4mq3vze.png)

→ **Canary, NX, PIE, and Full RelRO** are enabled. Fortify is disabled.

**Program menu:**

```
$ ./chall_patched 

== Heap Basic V2 ==
1. Create
2. Read
3. Edit
4. Delete
> Session closed
```

Four options:
- **1. Create**: creates a chunk with user-defined size
- **2. Read**: reads data from a previously created index
- **3. Edit**: modifies data at a previously created index
- **4. Delete**: frees a chunk *(suspicious!)*

**Decompiled Delete function:**

![Ghidra Delete](https://hackmd.io/_uploads/rJvta53vMl.png)

→ The chunk pointer is **not NULLed** after `free()` → **UAF (Use-After-Free)** vulnerability!

Since **Full RelRO** is enabled, we can't overwrite any GOT address.

→ Strategy: **House of Apple 2** — modify the `stdout` FILE object.

## 3. Strategy

For House of Apple 2 we need to leak:
- **Libc address** (via `main_arena` from unsorted bin)
- **Heap address** (via `fd` pointer from tcache bin)

**Chunk layout:**

```
chunk[0] - Create: size 0x500  → Leak libc (unsorted bin → main_arena fd)
chunk[1] - Create: size 0x200  → Guard chunk (prevent top chunk consolidation)
chunk[2] - Create: size 0x100  → Tcache poisoning target
chunk[3] - Create: size 0x100  → Tcache poisoning target
```

**Addresses we obtain:**
- `system()` address from libc leak
- `_IO_2_1_stdout_` address from libc leak
- `_IO_wfile_jumps` address from libc leak
- Heap chunk addresses

**Leak heap address from tcache fd pointers:**

```
Create chunk[2]
Create chunk[3]
Free chunk[3]  → tcache bin: [chunk[3]]
Free chunk[2]  → tcache bin: [chunk[2]] → [chunk[3]]  (LIFO)
```

The freed chunks are managed by `fd` pointers. We can read them using option **2 (Read)** (UAF).

> **Note:** In glibc ≥ 2.32, tcache fd pointers are **XOR-obfuscated** (Safe-Linking). Must decode: `heap_addr = fd ^ (chunk_addr >> 12)`.

## 4. House of Apple 2 — Hijack stdout

Using tcache poisoning, allocate a fake chunk overlapping `_IO_2_1_stdout_`, then craft a fake FILE object to call `system("/bin/sh")` when `flushing` occurs.

Key fields to set in the fake `_IO_FILE`:
- `_flags = 0x3b01010101010101` (magic value)
- `_IO_write_base`, `_IO_write_ptr` → trigger write path
- `_wide_data->_IO_write_base` → `&system`
- `vtable` → `_IO_wfile_jumps`

```python
from pwn import *

# ... setup, leaks, tcache poisoning ...

fake_file  = flat(
    0x3b01010101010101,  # _flags
    ...
)
# Allocate over stdout, send fake_file
# Trigger: any output operation → system("/bin/sh")
```
