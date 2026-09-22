---
title: "[Dreamhack] pwn-library - Write up"
date: 2024-01-16 00:00:00 +0700
categories: [Dreamhack, Heap Exploitation]
tags: [pwn, heap, oob, dreamhack]
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
		return 1;
	}
	if(!strcmp(listbook[booksize-1].bookname, "-----returned-----")){
		printf("[*] you alreay returns last book!\n");
		return 1;
	}
	free(listbook[booksize-1].contents);
	memset(listbook[booksize-1].bookname, 0, 0x20);
	strcpy(listbook[booksize-1].bookname, "-----returned-----");
	printf("[*] lastest book returned!\n");
	return 0;
}

int steal_book(){
	FILE *fp = 0;
	__uint32_t filesize = 0;
	__uint32_t pages = 0;
	char buf[0x100] = {0, };
	printf("[*] Welcome to steal book menu!\n");
	printf("[!] caution. it is illegal!\n");
	printf("[+] whatever, where is the book? : ");
	scanf("%144s", buf);
	fp = fopen(buf, "r");
	if(!fp){
		printf("[*] we can not find a book...\n");
		return 1;
	} else {
		fseek(fp, 0, SEEK_END);
    	filesize = ftell(fp);
    	fseek(fp, 0, SEEK_SET);
		printf("[*] how many pages?(MAX 400) : ");
		scanf("%u", &pages);
		if(pages > 0x190){
			printf("[*] it is heavy!!\n");
			return 1;
		}
		if(filesize > pages){
			filesize = pages;
		}
		secretbook.contents = (char *)malloc(pages); // this is heap memory will be allocated
		memset(secretbook.contents, 0x0, pages);
		__uint32_t result = fread(secretbook.contents, 1, filesize, fp);

		if(result != filesize){
			printf("[*] result : %u\n", result);
			printf("[*] it is locked..\n");
			return 1;
		}
		
		memset(secretbook.bookname, 0, 0x20);
		strcpy(secretbook.bookname, "STOLEN BOOK");
		printf("\n[*] (Siren rangs) (Siren rangs)\n");
		printf("[*] Oops.. cops take your book..\n");
		fclose(fp);
		return 0;
	}

}


void menuprint(){
	printf("1. borrow book\n");
	printf("2. read book\n");
	printf("3. return book\n");
	printf("4. exit library\n");
}
void main(){
	__uint32_t select = 0;
	printf("\n[*] Welcome to library!\n");
	setvbuf(stdin, 0, 2, 0);
	setvbuf(stdout, 0, 2, 0);
	while(1){
		menuprint();
		printf("[+] Select menu : ");
		scanf("%u", &select);
		switch(select){
			case 1:
				borrow_book();
				break;
			case 2:
				read_book();
				break;
			case 3:
				return_book();
				break;
			case 4:
				printf("Good Bye!");
				exit(0);
				break;
			case 0x113:
				steal_book();
				break;
			default:
				printf("Wrong menu...\n");
				break;
		}
	}
}
```

This program four main actions are borrow, read, return, steal book. Then I analyzed I realize that we can read secret data on the server by choose option: 275 (case 0x113). This looks like a backdoor intentionally left by developer.

So we need to analyze steal_book function:
+ Steal_book will based-on the address which was typed by user. 
+ Value of pages must be less than or equal to 0x190 bytes.
+ The contents of the target are coppied into a newly allocated heap chunk. 

In retur_book(). After calling free() the pointer is not set to NULL. As a result, listbook[idx].contents still point to the freed heap chunk  -> resulting in a Use After Free vulnerability.

Based-on this, we can leak data from server through this program.
+ The first, we borrow a book whose content size less than or equal to 0x190 -> Option 1: ("1. theori theory" with 0x100 pages) 
+ The second, we return the book which we just borrow. (Now the chunk of the contents memory area is allocated in bin heap).
+ The third, we type 275 to activate steal_book function and the enter the path which lead to the flag is [/home/pwnlibrary/flag.txt](https://). And then enter 256 bytes(0x100) as the page size this equal with the chunk was freed in bin heap. Since the allocator reuse the freed chunk, the flag is written into heap chunk previously referenced by listbook[0].contents.
+  The last activate read_book function to display data of the flag out of screen. (Because listbook[0].contents still contains a dangling pointer freed chunk). So when we read at idx=0 the pointer in listbook will read data at the chunk in heap bin which is reuse in third step.

![image](https://hackmd.io/_uploads/BJLZvvyHMe.png)

Good luck!!