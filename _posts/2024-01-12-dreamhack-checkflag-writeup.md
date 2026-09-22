---
title: "[Dreamhack] checkflag - Write up"
date: 2024-01-12 00:00:00 +0700
categories: [Dreamhack, Binary Exploitation]
tags: [pwn, stack-overflow, strcmp, dreamhack]
author: datious
---

[Write up for dreamhack]__Challenge: checkflag | Author: datious

checkflag.c
```
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
  fp = fopen("flag","r");
  if (fp != (FILE *)0x0) {
    fgets(flag,0x40,fp);
    fclose(fp);
    fputs("What's the flag? ",stdout);
    fflush(stdout);
    sVar2 = read(0,input,200);
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
      cmp = strcmp(input,flag);
      if (cmp == 0) {
        fputs("Correct!\n",fp);
        if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
          __stack_chk_fail();
        }
        return 0;
      }
    }
    fputs("Failed!\n",fp);
  }
                    /* WARNING: Subroutine does not return */
  exit(1);
}

```

The vulnerability is a buffer overflow.
The program allows entering up to 200 bytes into the **input** buffer, which is only allocated 64 bytes. This enables us to overwrite the adjacent stack memory, where the **flag** variable resides.
1. Analyzing and gathering
- Check security layers:
![image](https://hackmd.io/_uploads/H1ISbOZ8fx.png)

- I used GDB to inspect the stack layout upon user input.
 ![image](https://hackmd.io/_uploads/HJrhbubLzg.png)
- As shown above, the flag is located directly below input on the stack.
- Back to the main function: the program just returns **correct!** when **strcmp(input,flag)** returns 0 => Both of the strings have to equal.
- Analyzing strcmp() function:
```
int mystrcmp(const char *s1, const char *s2
