### Writeup
开始界面是个菜单界面，可以创建、删除、运行函数

逆向得知，虚拟机有如下指令
```
hex info
0   loadi reg, inst
1   load w, reg, reg2, offset
2   save w, reg, reg2, offset
3   mov reg1, reg2 (4bit padding)
4   add reg, reg1, reg2
5   sub reg, reg1, reg2
6   and reg, reg1, reg2
7   or reg, reg1, reg2
8   xor reg, reg1, reg2
9   not reg, reg1 (4bit padding) 
a   push reg 
b   pop reg 
c   call funcid
d   ret reg
e   cmp reg1, reg2 (4bit padding)
f   b cond, offset

inst 8byte offset 4byte
```
虚拟机有两类地址：
* 栈地址：`0x0100000000000000` + 偏移，对应 bss 段上虚拟机栈的对应偏移，地址转换时候有范围检查。
* 代码地址：`0xP200000000000000` + 偏移 + 随机偏移，P 位置为函数 id，

检查后发现 `load` 和 `save` 指令访问函数代码上的地址时候没有检查，并且删除函数时没有将指向函数代码的指针设为 `NULL`

于是可以构造一个 UAF，通过 `load` 指令，读取 unsorted bin 中 chunk 的 fd 泄露 libc 地址。

由于存在随机偏移，需要进入到该 chunk 对应函数的代码中，再根据 ip 寄存器的值，以此获取到对应的代码段地址。

但 `call` 指令会检查该函数的 length 是不是为 0，被删除的函数的length会被置0，所以我们需要伪造函数栈，然后通过 `ret` 指令劫持控制流到我们想要的函数中。

但我们不知道我们要进入的函数的随机偏移，我们发现随机偏移的范围是 `0~114`，我们可以给要进入的函数中添加无用指令，填充 114 个字节，然后要返回到的地址可以写成 `0xP200000000000114 + padding_offset` 

通过上述方法 leak libc 后，我们需要使用 TCache Attack 去修改 free_hook 为 system，写一个将 fd 写为 `free_hook - 8` 的虚拟机程序，然后构造一个函数（类似 leak libc 时候返回到的函数），再将其删除，利用我们构造的写入程序，控制返回地址到被删除的函数，获得代码段地址，然后修改 TCache 中 刚刚被 free 的 chunk 的 fd，然后通过两次 malloc 获取到一个起始地址在 `free_hook - 8` 的 chunk，前 8 个字节为 `'/bin/sh\x00'`，然后覆盖 `free_hook` 为 `system` 的地址，最后 free 掉这个 chunk，成功 getshell 