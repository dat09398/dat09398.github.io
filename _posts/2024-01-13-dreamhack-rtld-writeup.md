---
title: "[Dreamhack] rtld - Write up"
date: 2024-01-13 00:00:00 +0700
categories: [Dreamhack, Binary Exploitation]
tags: [pwn, arbitrary-write, ld-so, rtld, one-gadget, dreamhack]
author: datious
---

[Write up for dreamhack]__Challenge: rtld | Author: datious

1. Analyzing the source code
rtld.c
```
// gcc -o rtld rtld.c -fPIC -pie

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <dlfcn.h>

void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}

void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGALRM, alarm_handler);
    alarm(60);
}

void get_shell() {
    system("/bin/sh");
}

int main()
{
    long addr;
    long value; 

    initialize();

    printf("stdout: %p\n", stdout);

    printf("addr: ");
    scanf("%ld", &addr);

    printf("value: ");
    scanf("%ld", &value);

    *(long *)addr = value;
    return 0;
}

```
Checksec: PIE, Partial RelRO, Canary found, NX enable.
The program provides:
    - stdout address: the value of stdout pointer, it points to **_IO_2_1_stdout_** struction into libc.
    - Allowing user write 8 bytes into any address  ****(long*)addr=value**  , no limit.

We don't have any ways to leak binary address, so we can't return to get_shell() function.

But I found three one_gadgets in the libc file. We can use this to execute  **execve("/bin/sh").**

2. The idea to exploit: Hijack the function pointer in **ld.so**
- After main() return, glibc constant run exit()-> __run_exit_handlers() -> _dl_fini() (in ld.so), it have responsible to run destructor of others shared object was loaded. Before inspection, it lock a mutex by macro.

```
#define __rtld_lock_lock_recursive(NAME) \
    GL(dl_rtld_lock_recursive) (&(NAME).mutex)

void _dl_fini(void) {
    ...
    __rtld_lock_lock_recursive(GL(dl_load_lock));   // gọi qua CON TRỎ HÀM
    ...
}
```
GL(dl_rtld_lock_recursive) is a pointer funtion placed in global struction, _rtld_global inside ld.so, always is called when program exit- Not depend on code of rtld.c.

- Strategy: use arbitrary-write for overwrite this pointer by one_gadgets address in libc. When _dl_fini is running, it's unintentional call one_gadgets -> execve("/bin/sh").

3. Calculate addresses.
```
leak (stdout):
-> libc_base=leak-offset(_IO_2_1_stdout_) # 0x3c5620 with libc-2.23 version.
-> ld_base= libc_base+offset_GAP(from libc base to ld base).
-> rtld_global=ld_base+offset_to_rtld_global (0x226040). _rtld_global in ld.so
-> dl_rtld_lock_recursive = _rtld_global + 0xf08 (field offset of function)

Write:
    addr = dl_rtld_lock_recursive
    value = libc.address+ one_gadgets offset


```

4. Stuck on solving processing and how to debug.
- The GAP(libc->ld.so) value was wrong:
    + The first time, I used GAP = 0x400000 (guessing each pattern which is usually matched) -> Running on local is pass, running on server is fail. Th
