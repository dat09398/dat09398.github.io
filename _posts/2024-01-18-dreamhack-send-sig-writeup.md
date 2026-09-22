---
title: "[Dreamhack] send_sig - Write up"
date: 2024-01-18 00:00:00 +0700
categories: [Dreamhack, Binary Exploitation]
tags: [pwn, srop, sigreturn, rop, syscall, dreamhack]
author: datious
---

[Write up for dreamhack]__Challenge: send_sig | Author: datious

vuln.c
```
void vuln(void)

{
  undefined1 local_10 [8];
  
  write(1,"Signal:",7);
  read(0,local_10,0x400);
  return;
}

```
- This is a Buffer Overflow vulnerability.
- Through this function, we can overwrite RIP register and control the control flow of the program. 

Now, let's check protection layers of the program.
![image](https://hackmd.io/_uploads/S1A5LCHBMl.png)

- NX is on. So we can't return to shellcode.
-  The ROP (Return-Oriented Programming) technique also does not have enough gadgets for the exploitation.
- During reconnaissance, I found a very important detail. The presence of a syscall, pop_rax gadgets, and a "/bin/sh" string within the binary.
![image](https://hackmd.io/_uploads/Bknqt0rrze.png)

![image](https://hackmd.io/_uploads/r15GcASBfl.png)

Based on this, my approach is to leverage the SROP (Sigreturn Return-Oriented Programming) technique for this challenge.
- First, we return to the pop_rax gadget to set RAX to 15 (The syscall number for **rt_sigreturn**). The kernel will perform **rt_sigreturn** to set the status of the registers before.
- When the kernel performs **rt_sigreturn
