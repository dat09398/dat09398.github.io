---
title: "Pwn4- MiniCTF-PTITHCM"
date: 2024-01-06 00:00:00 +0700
categories: [CTF, Binary Exploitation]
tags: [pwn, shellcode, gets, stack-overflow, ptithcm]
author: datious
---

# Pwn4- MiniCTF-PTITHCM
*Author: D1n0_09-N24DCAT015*
Đầu tiên khi tải về ta sẽ có 1 file pwn4.rar => Giải nén nó thì ta nhận được các file sau
![image](https://hackmd.io/_uploads/rJgQWTggbx.png)
* Tạo môi trường - Dùng tool pwinit để tạo file patched giữa file binary và file libc do bài cung cấp.
1.  Bước đầu tiên ta dùng gdb check thử các lớp bảo mật ma chương trình có 
![image](https://hackmd.io/_uploads/By9tVaelWe.png)

- Tất cả các lớp bảo mật đều tắt. Tiếp theo ta mở source code để tìm lỗ hổng. Dùng tool ghidra để decompile.
```
int main(void)

{
  char buf [32];
  
  dump_stack();
  printf("Input: ");
  gets(buf);
  printf("Output: ");
  printf(buf);
  putchar(10);
  dump_stack();
  return 0;
}
```
- Đây là hàm main của chuong trình. Lỗi ở đây là hàm gets() cho nhập không giới hạn trong khi kích thươc của biến buf là 32 => buffer overflow.
=> Qua đây em quyết định sử dụng shellcode để return vào nó thông qua việc ghi đè save rip nhằm điều khiển chương trình.
//shellcode
2. Khai thác 
- Đầu tiên phải xác nhận offset từ biến buf tới save rip
- Vì đây là cấu trúc 64bit nên mỗi thanh ghi gồm 8 bytes.
=> Nhập thử với buf có độ lớn 48 bytes

![image](https://hackmd.io/_uploads/SJjLdTgeWl.png)
- Từ đây ta có biết được offset=40
- Ngoài ra khi run chuong trình còn cung cấp địa chỉ của biến buf như này
``
