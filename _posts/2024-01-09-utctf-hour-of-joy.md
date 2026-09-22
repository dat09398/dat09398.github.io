---
title: "UTCTF - Binary exploitation - Hour Of Joy"
date: 2024-01-09 00:00:00 +0700
categories: [CTF, Binary Exploitation]
tags: [pwn, format-string, utctf, reverse]
author: datious
---

# UTCTF - Binary exploitation - Hour Of Joy
Author: D1n0_09

- Main function:
                
                *undefined8 main(void)

{
  size_t sVar1;
  int buffer;
  char name [76];
  int local_c;
  
  setup();
  local_c = -559038737;
  printf("What is your name? ");
  fgets(name,0x40,stdin);
  sVar1 = strcspn(name,"\n");
  name[sVar1] = '\0';
  printf("Hello, ");
  printf(name);
  puts("!");
  printf("Enter the secret code: ");
  __isoc99_scanf(&DAT_0010203c,&buffer);
  if (buffer == local_c) {
    print_flag();
  }
  else {
    puts("Wrong! Nice try.");
  }
  return 0;
}
*

- Bài này giống reverse hơn pwn 
- Nh
