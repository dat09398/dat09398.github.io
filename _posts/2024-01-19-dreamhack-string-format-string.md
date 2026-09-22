---
title: "[Dreamhack] string - Write up"
date: 2024-01-19 00:00:00 +0700
categories: [Dreamhack, Binary Exploitation]
tags: [pwn, format-string, got-overwrite, warnx, libc-leak, dreamhack]
author: datious
---

[Write up for dreamhack]__Challenge: **string** | Author: datious

string.c 
```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}

void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    close(2);
    dup2(1, 2);

    signal(SIGALRM, alarm_handler);
    alarm(60);
}


void input(char *buf) {
	printf("Input: ");
	read(0, buf, 255);
}

void print(char *buf) {
	warnx(buf);
}

int main() {

	int idx;
	char buf[256];

	initialize();

	memset(buf, 0, sizeof(buf));

	while(1) {
		printf("1. Input\n");
		printf("2. Print\n");
		printf("3. Exit\n");
		printf("> ");

		scanf("%d", &idx);
		switch(idx) {
			case 1:
				input(buf);
				break;
			case 2:
				print(buf);
				break;
			default:
				break;
		}
	}
	return 0;
}

```

The vulnerability in this challenge is format string. You can see that in print() function.

# Let analyze format string vulnerability in print() function:
- The **warnx()** was declaired in #include **<err.h> library.**
- This have prototype likes ***void warnx(const char *fmt, ...);***
- **Warnx()** works like **fprintf(stderr, fmt, ...);**
- The example is **char *buf="AAAA"**, the warnx() will work like **warnx(buf)**.
-  If user types** "%x%x%x"** into the buf, **warnx() **will operate **fprintf(stderr, "%x %x %x %x");** -> format string vulnerability -> leak data in memory.

Now, let check protection of program by GDB.

![image](https://hackmd.io/_uploads/rykvU2-HGg.png)

My idea is overwrite GOT address.
Because the challenge provides with libc.so.6 so we can use format string vulnerability to leak libc address and find system() address for overwrite 
