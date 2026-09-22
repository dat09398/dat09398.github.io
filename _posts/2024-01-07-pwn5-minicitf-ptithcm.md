---
title: "Pwn5 - MiniCTF - PTITHCM"
date: 2024-01-07 00:00:00 +0700
categories: [CTF, Binary Exploitation]
tags: [pwn, shellcode, gets, stack-overflow, ptithcm]
author: datious
---

# Pwn5 - MiniCTF - PTITHCM
*Author: D1n0_09-N24DCAT015*

Bài pwn5 này có phuong pháp khai thác tương tự pwn4

1. Tìm lỗ hổng
- Giải nén ta được các thư mục chứa các file như sau 
 ![image](https://hackmd.io/_uploads/Sy4hhallWe.png)
- Dùng pwninit để patched các file tạo môi trường cho file binary.
- Chạy thử file binary patched.
```
(pwnenv)─(kali㉿kali)-[~/Downloads/pwn5]
└─$ ./chall_patched 
0x7ffcd3ef37d0: 0000000000000000 <- rsp
0x7ffcd3ef37d8: 00007fac2ae354e0 
0x7ffcd3ef37e0: 00007ffcd3ef3820 
0x7ffcd3ef37e8: 00007fac2ac9d451 
0x7ffcd3ef37f0: 00007ffcd3ef3890 <- rbp
0x7ffcd3ef37f8: 00007fac2ac2a575 
Input: 

```
- Đã có địa chỉ để nhảy vào khi tạo shellcode trên stack
- Mở ghidra để tìm lỗ hổng
```
int main(void)

{
  char buf [32];
  
  dump_stack();
  printf("Input: ");
  gets(buf);
  printf("Output: ");
  printf(buf);
  putchar(10);
  dump_stack();
  return 0;
}
```
- Lỗi buffer overflow tại hàm gets cho nhập không giới hạn.
* Checksec => Đây la bước quan trọng để đưa ra hướng khai thác
```
gef➤  checksec
[+] checksec for '/home/kali/Downloads/pwn5/chall_patched'
Canary                        : ✘ 
NX                            : ✘ 
PIE                           : ✘ 
Fortify                       : ✘ 
RelRO           
