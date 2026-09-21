---
title: "OUT-OF-BOUND BUG"
date: 2024-01-01 00:00:00 +0700
categories: [Binary Exploitation, Out-of-Bound]
tags: [pwn, oob, heap, ghidra]
author: datious
description: "Analysis of an Out-of-Bound bug in a bank account management binary, exploiting negative index to access arbitrary memory."
---

# OUT-OF-BOUND BUG
**Author: D1n0_09**

This related to index in the array.

```c
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
          puts("You didn't create this account!");
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

## Vulnerability

The program checks `index < 10` but **does NOT check for negative values**. Since `index` is declared as `int` (signed), the user can supply negative values. This allows accessing memory outside the `acc[]` array bounds — a classic Out-of-Bound (OOB) bug.

- `acc + (long)index * 0x10` with a negative index will point to addresses **before** the `acc` array in the BSS segment.
- This can be leveraged to read/write arbitrary global data, including GOT entries.

## Exploitation

By supplying a carefully crafted negative index, we can:
1. Point to a GOT entry (e.g., `free@GOT` or `puts@GOT`)
2. Overwrite it with a `one_gadget` or `system()` address
3. Trigger the function call to get a shell

> **Tip:** Calculate the negative index as: `index = (target_addr - acc_addr) / 0x10`
