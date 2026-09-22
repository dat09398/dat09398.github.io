---
title: "Pwn3-MiniCTF-PTITHCM"
date: 2024-01-05 00:00:00 +0700
categories: [CTF, Binary Exploitation]
tags: [pwn, ret2shellcode, canary-leak, stack-overflow, ptithcm]
author: datious
---

# Pwn3-MiniCTF-PTITHCM
*Author: D1n0_09-N24DCAT015*

* Đầu tiên server sẽ cho ta 1 file có tên ret2shellcode => Dự đoán khai thác bằng cách overwrite save rip để return vào shellcode.
1. Tổng quát về file thực thi.
* Đầu tiên em dùng ghidra để decompile file bin thành source code có thể đọc được.
```

void main(void)

{
  long in_FS_OFFSET;
  undefined1 local_118 [264];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  printf("%p",local_118);
  printf("\nWelcome to our CTF");
  printf("\nTo play our CTF, please register an account:");
  printf("\nPlease enter your username: ");
  fflush(stdout);
  hehe();
  read(0,local_118,0x10a);
  printf("Your user name: %s",local_118);
  printf("\nEnter your password: ");
  memset(local_118,0,0x100);
  fflush(stdout);
  read(0,local_118,0x120);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}

```
=> Đây là code của hàm main. 
* Ta có thể thấy lỗi buffer overflow ở cả 2 hàm read()
* Check thử các lớp bảo mật.
![image](https://hackmd.io/_uploads/rkdXmZQebg.png)
=> Canary bật vậy không thể trực tiếp overwrite save rip được. Nhưng ở hàm main còn 1 lỗi nữa đó chính là hàm printf() ở hàm này nó sẽ đọc dữ liệu trên cho tới khi gặp null byte mà canary có byte đầu tiên là null byte.
=> Hướng khai thác sẽ leak canary để vượt mặt lớp bảo vệ này.
2. Khai thác
*Lần nhập đầu tiên chương trình cho nhập 266 bytes mà biến này giới hạn chỉ 264 bytes nên ta thử nhập payload có độ lớn 266 bytes.
![image](https://hackmd.io/_uploads/BJAoN-7ebg.png)
  Canary nằm phía trên save rbp ta có thể thấy nó đã ghi đè 2 bytes của canary => Vậy ta cần nhập payload đầu có độ lớn là 265 bytes => leak được canary mà vẫn đảm bảo khôi phục lại sau leak.
* Vậy đã có được canary.
* Bước tiếp theo là shellcode: để thực hiện ta cần shellcode và địa chỉ để nhảy đúng vào nó.
* Khi chạy chuong trình ta thấy nó cung cấp cho ta 1 địa chỉ:
![image](https://hackmd.io/_uploads/SJJZ8bXxWx.png)
* Đã đầy đủ nguyên liệu để bypass và lấy được quyền điều khiển.
