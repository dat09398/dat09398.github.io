---
title: "[Dreamhack] IO_FILE Arbitrary Address Read - Write up"
date: 2024-01-14 00:00:00 +0700
categories: [Dreamhack, Binary Exploitation]
tags: [pwn, io-file, file-struct, arbitrary-read, dreamhack]
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
_IO_
