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
  exi
