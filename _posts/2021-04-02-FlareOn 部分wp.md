---
layout: post
title: FlareOn 部分wp
subheading: 学点Reverse
author: Te4P0t
categories: 无
tags: Reverse FlareOn
---


## FlareOn 部分wp



#### [FlareOn4]login

打开网页，要求输入flag。

f12审查元素。

![image-20210403151947816](https://te4p0t.github.io/assets/images/typora-user-images/image-20210403151947816.png)

加密用了两个三目运算符，乍看很烦。稍加分析不难看出是rot13加密。

rot13有个简单的性质，对rot13加密所得密文再进行rot13加密，就可以得到明文。

直接借用该题代码

![image-20210403153956395](https://te4p0t.github.io/assets/images/typora-user-images/image-20210403153956395.png)



#### [FlareOn6]Overlong

Overlong.exe，直接运行，弹出框。

![image-20210403154944713](https://te4p0t.github.io/assets/images/typora-user-images/image-20210403154944713.png)

好像没啥信息，但这句话和最后的“：”都是伏笔。

拖入IDA

![image-20210403155047379](https://te4p0t.github.io/assets/images/typora-user-images/image-20210403155047379.png)

MessageBoxA应该就是弹出窗口的函数。

sub_401160内是加密函数，unk_402008是加密的内容，28是长度。

观察unk_402008的内容，发现一直从0x402008到0x4020B7，远超28。

再结合overlong和之前的伏笔，那么将28改大应该就能看见flag。

用OD打开动态调试，将28改大后继续运行。得到flag

![image-20210403160916549](https://te4p0t.github.io/assets/images/typora-user-images/image-20210403160916549.png)



#### [FlareOn4]IgniteMe

IgniteMe.exe 要求输入flag，拖入IDA。

![image-20210403192255469](https://te4p0t.github.io/assets/images/typora-user-images/image-20210403192255469.png)

找到加密函数，其中byte_403078是输入的字符串，v1是长度。一个循环倒序异或。根据异或性质b = a^b^a可以根据密文反求明文。之后进行比较的byte_403000中是加密后的密文。那么关键就在于v4的值是啥。

可以用od调试查看，当sub_401000函数执行后eax的值。

![image-20210403192624706](https://te4p0t.github.io/assets/images/typora-user-images/image-20210403192624706.png)

v4是char类型，取低二位就是4。那么v4的初值也知道了。写个脚本。

```python
cipher = [0x0d, 0x26, 0x49, 0x45, 0x2a, 0x17, 0x78, 0x44, 0x2b, 0x6c, 0x5d, 0x5e, 0x45, 0x12, 0x2f, 0x17, 0x2b, 0x44, 0x6f, 0x6e, 0x56, 0x9, 0x5f, 0x45, 0x47, 0x73, 0x26, 0xa, 0xd, 0x13, 0x17, 0x48, 0x42, 0x1, 0x40, 0x4d, 0xc, 0x2, 0x69]
a = 4
flag = cipher
for i in range(len(cipher)-1,-1,-1):
    flag[i] = cipher[i] ^ a
    a = flag[i]

for i in flag:
    print(chr(i), end='')
print('')
```

![image-20210403192810224](https://te4p0t.github.io/assets/images/typora-user-images/image-20210403192810224.png)



#### [FlareOn2]starter

exe文件，执行，要求输入flag。

拖入IDA.

![image-20210403194016171](https://te4p0t.github.io/assets/images/typora-user-images/image-20210403194016171.png)

byte_402158为输入字符串，每次与0x7d异或后与byte_402140比较，找到byte_402140中内容写脚本。

```python
a = [0x1f, 0x8, 0x13, 0x13, 0x4, 0x22, 0xe, 0x11, 0x4d, 0xd, 0x18, 0x3d, 0x1b, 0x11, 0x1c, 0xf, 0x18, 0x50, 0x12, 0x13, 0x53, 0x1e, 0x12, 0x10]
for i in a:
    print(chr(i^0x7d), end='')
print('')
```

![image-20210403194206095](https://te4p0t.github.io/assets/images/typora-user-images/image-20210403194206095.png)





#### [FlareOn2]very_success

very_success.exe，打开后和之前一样，要求输入密码。

拖进IDA分析。

![image-20210403141256374](https://te4p0t.github.io/assets/images/typora-user-images/image-20210403141256374.png)

if判断里一个函数，返回true即success。

点进sub_401084查看。

![image-20210403141523861](https://te4p0t.github.io/assets/images/typora-user-images/image-20210403141523861.png)

一个加密函数。输入字符串的长度要大于等于37。v7初值是a2+36，每次循环减1，且指向内容在每次循环中都与加密后的输入内容进行比较。那么a2地址存储的就是加密后的密码。

分析v12，3个值相加，分别为 1左移v4 & 3位、 v11、v10。

v4初值0，每次循环加v12（和v7等值），v10是v15 ^ v8。而v15是result（即0x1c7），v8是输入的数。那么3个值中的两个已知，关键在v11是啥。

![image-20210403142124871](https://te4p0t.github.io/assets/images/typora-user-images/image-20210403142124871.png)

返回汇编代码分析。之前的伪c语句都能找到对应语段。分析发现ax寄存器是0x1c7，但在xor时用的是al（ax低8位），所以上述的v15是（0xc7)。并且我们注意到该段代码中对al和ah用的是adc指令而非add。而adc是在add的基础上加了进位标志符CF。因此v11的值应该是CF中的值，那CF是什么值呢？

在此之前有一个指令sahf。作用是将ah存至FLAG寄存器低8位。ah（ax高8位）是0x1，而FLAG最低位就是CF的值。也就是该指令结束后，CF的值变为1。破案了，每次循环v11的值均为1。

加密后的字符串也可以在IDA中找到

![image-20210403150529380](https://te4p0t.github.io/assets/images/typora-user-images/image-20210403150529380.png)

到此这题就很清楚了，已知v12，根据加密算法求v8。v12=rol(1, v4 & 3) + v11 + v10。 其中，v12、rol(1, v4 & 3)、v11都已知，可求得v10。而v10=v15 ^ v8。v15是0xc7，根据异或运算性质b = a^b^a可求v8 = v15^v8^v15 = v10^v15。

写个脚本

```python
cipher = [0xa8, 0x9a, 0x90, 0xb3, 0xb6, 0xbc, 0xb4, 0xab, 0x9d, 0xae, 0xf9, 0xb8, 0x9d, 0xb8, 0xaf, 0xba, 0xa5, 0xa5, 0xba, 0x9a, 0xbc, 0xb0, 0xa7, 0xc0, 0x8a, 0xaa, 0xae, 0xaf, 0xba, 0xa4, 0xec, 0xaa, 0xae, 0xeb, 0xad, 0xaa, 0xaf]
flag = ''
v4 = 0
for i in cipher:
    v10 = (i - 1 - (1 << (v4 & 3)))
    flag += chr(v10 ^ 0xc7)
    v4 += i
print(flag)
```

![image-20210403151552454](https://te4p0t.github.io/assets/images/typora-user-images/image-20210403151552454.png)