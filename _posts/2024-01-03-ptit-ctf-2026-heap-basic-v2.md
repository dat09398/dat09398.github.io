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
- However, I realized that the fd pointer 
