---
title: "[Dreamhack] pwn-library - Write up"
date: 2024-01-16 00:00:00 +0700
categories: [Dreamhack, Heap Exploitation]
tags: [pwn, heap, oob, global-variable, dreamhack]
author: datious
---

[Write up for Dreamhack]__Challenge: **pwn-library**      | Author: datious

Library.c
```
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

struct bookstruct{
	char bookname[0x20];
	char* contents;
};

__uint32_t booksize;
struct bookstruct listbook[0x50];
struct bookstruct secretbook;

void booklist(){
	printf("1. theori theory\n");
	printf("2. dreamhack theory\n");
	printf("3. einstein theory\n");
}

int borrow_book(){
	if(booksize >= 0x50){
		printf("[*] book storage is full!\n");
		return 1;
	}
	__uint32_t select = 0;
	printf("[*] Welcome to borrow book menu!\n");
	booklist();
	printf("[+] what book do you want to borrow? : ");
	scanf("%u", &select);
	if(select == 1){
		strcpy(listbook[booksize].bookname, "theori theory");
		listbook[booksize].contents = (char *)malloc(0x100);
		memset(listbook[booksize].contents, 0x0, 0x100);
		strcpy(listbook[booksize].contents, "theori is theori!");
	} else if(select == 2){
		strcpy(listbook[booksize].bookname, "dreamhack theory");
		listbook[booksize].contents = (char *)malloc(0x200);
		memset(listbook[booksize].contents, 0x0, 0x200);
		strcpy(listbook[booksize].contents, "dreamhack is dreamhack!");
	} else if(select == 3){
		strcpy(listbook[booksize].bookname, "einstein theory");
		listbook[booksize].contents = (char *)malloc(0x300);
		memset(listbook[booksize].contents, 0x0, 0x300);
		strcpy(listbook[booksize].contents, "einstein is einstein!");

	} else{
		printf("[*] no book...\n");
		return 1;
	}
	printf("book create complete!\n");
	booksize++;
	return 0;
}

int read_book(){
	__uint32_t select = 0;
	printf("[*] Welcome to read book menu!\n");
	if(!booksize){
		printf("[*] no book here..\n");
		return 0;
	}
	for(__uint32_t i = 0; i<booksize; i++){
		printf("%u : %s\n", i, listbook[i].bookname);
	}
	printf("[+] what book do you want to read? : ");
	scanf("%u", &select);
	if(select > booksize-1){
		printf("[*] no more book!\n");
		return 1;
	}
	printf("[*] book contents below [*]\n");
	printf("%s\n\n", listbook[select].contents);
	return 0;
}

int return_book(){
	printf("[*] Welcome to return book menu!\n");
	if(!booksize){
		printf("[*] no book here..\n");
		retur
