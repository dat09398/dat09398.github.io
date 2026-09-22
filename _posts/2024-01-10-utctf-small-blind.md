---
title: "UTCTF - Binary exploitation - Small Blind"
date: 2024-01-10 00:00:00 +0700
categories: [CTF, Binary Exploitation]
tags: [pwn, format-string, leak, utctf]
author: datious
---

# UTCTF - Binary exploitation - Small Blind
Author: D1n0_09

![image](https://hackmd.io/_uploads/Bk-X3zEq-g.png)

- Đây là 1 challenge đoán cách để crack chuong trình khi đó chương trình sẽ check và đưa ra flag. Dựa vào phần description ta có thể đoán được chỉ khi chuong trình kết thúc và ta có được số chip vượt 1000 thì sẽ win.
1. Lỗ hổng
![image](https://hackmd.io/_uploads/HkmxpGNcbg.png)
- Nhìn vào đây có thể thấy rằng khi nhập %p thì sẽ leak được địa chỉ trên stack. ( Format string).
- Nhập cỡ 29 %p để xem leak được cái gì.

```
(pwnenv)─(kali㉿kali)-[~/Downloads/utctf]
└─$ python3 test.py
[q] Opening connection to challenge.utctf.live on port 7255: Trying 23.139.8[+] Opening connection to challenge.utctf.live on port 7255: Done
[+] Receiving all data: Done (1.27KB)
[*] Closed connection to challenge.utctf.live port 7255
╔══════════════════════════════════════════╗
║          ♣ ♦ Texas Hold'em ♥ ♠           ║
╠══════════════════════════════════════════╣
║  Small blind: 10    Bi
