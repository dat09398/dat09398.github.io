---
title: "OUT-OF-BOUND FROM DREAMHACK CHALLENGE"
date: 2024-01-02 00:00:00 +0700
categories: [Binary Exploitation, Out-of-Bound]
tags: [pwn, oob, dreamhack, system]
author: datious
---

OUT-OF-BOUND FROM DREAMHACK CHALLENGE
Author: D1n0_09 

Today I will solve a challenge that have a name is out of bound.
1. Cursory
- Program:
```
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>

char name[16];

char *command[10] = { "cat",
    "ls",
    "id",
    "ps",
    "file ./oob" };
void alarm_handler()
{
    puts("TIME OUT");
    exit(-1);
}

void initialize()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    signal(SIGALRM, alarm_handler);
    alarm(30);
}

int main()
{
    int idx;

    initialize();

    printf("Admin name: ");
    read(0, name, sizeof(name));
    printf("What do you want?: ");

    scanf("%d", &idx);

    system(command[idx]);

    return 0;
}

```
- I have some information from the program as follows:
    + Security layers:
  
>   checksec out_of_bound  
[*] '/home/kali/Downloads/dreamhack/out_of_bound'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
                     
                     
- When I analyze I saw a loophole. Idx was declared with data type of int. Therefor we can input numbers signed ,unsigned in the scale of int and command array just declaired ten elements. So when user input idx located outside command array they can access other datas in program.
2. Exploitation
- My idea is input the string '/bin/sh' in  name variable
