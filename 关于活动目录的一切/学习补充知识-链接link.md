### 第一部分 ：针对 csapp第七章链接这个章节的笔记学习总结：
链接可以被加载复制到内存并且执行 ，链接早起是手动的 现在 有一个叫走linker的执行
链接器的作用是 ：分离编译  也就是separate compilation 分离编译
可以进行部分编译跟分块儿编译过程
主要用途：
1 连接器帮助构造大型程序
2 链接器避免边恒错误，错误的定义变量信息等问题 
3 理解链接 语言的全局局部变量之间的差别 
4连接器产生的可执行的目标文还能再 虚拟内存等分页等程序中扮演重要的角色体系
5 能使用共享库 ，跟动态链接 ：动态链接以及动态共享库 
那么我们问题在于 当我们运行下面两段代码的时候 经过linux 中的gcc -Og 后发生了设呢么
![[Pasted image 20241115161943.png]]
这些在执行 一个 
`gcc -Og -o prog main.c sum.c`
后将其连接到了一起 并且 输出成了一个叫做prog的东西
![[Pasted image 20241115162258.png]]
我将有两段头文件的代码跟 两段无头文件的代码分别放在了一起做对比，发现不管是否有头文件海还是无头文件，都不影响这个ld后链接后的 文件生成 分别定义为了prog 跟progdlc

现在分析之前的指令数据：
`gcc -Og -o prog main.c sum.c`
-Og含义是：gcc 使用编译器的一种优化选项  优化级别0 采用基本优化来提高程序心梗，属于u调试友好的级别类型的
-o是告知系统我们用的是输出到文件的形式

当我们执行这些的时候发生了设呢么呢？
![[Pasted image 20241115162630.png]]
编译系统提供的编译器驱动程序，调用语言预处理编译器汇编跟链接器 各种部分，然后
先把main.c 经过cpp处理为一个 main.i 这个main.i是具有ASCII码的一个装置，
然后驱动器运行C编译器ccl 将main.i翻译成 ACII汇编文件main.s
再然后 驱动程序汇编器as 将main.s翻译成一个 可重定位的目标文件 main.o 
sum同理
shell调用的时候用了一个叫做加载器的loadeer的函数 将progexe的可执行文件代码数据复制到内存 ，并且转移到程序开头中去
### 7.2静态链接：
他是将 一组可重定位的目标文件 跟命令行参数作为输入，然后生成 一个 可执行目标文件作为输出
并且 输入的可重定位的目标文件 由不同代码跟数据节组成 ，每一个数据节不同 
第一个为 数据 第二个位指令等 ，全局变量在下一节中 那种概念
目标 ：从.o 链接称为 .exe 或者.elf  
ldd完成以下两个主要任务：
任务1 ：符号解析：将符号进行记忆布的解析  c语言中 任何以static属性声明的变量 包含 函数，全局变量啊 ，静态变量 记性解析 ，且他们可以将符号引用跟定义关联起来
符号引用=>符号定义
什么是符号引用 什么是符号定义：
（1）：函数定义：代码中编写函数的时候 实际上定义这个符号，并且定义函数的时候编译器分配一个地址 
符号定义：符号内存地址为实际的内存地址，且每个符号只能在一个地方被定义一次
（2）符号引用：代码使用某个已经定义的符号，但是没再次定义它，而是引用它 而不是从新定义它
一个符号引用对应一个符号定义 防止重复定义的发生
任务2：重定位：编译器加汇编=从地址0开始的代码跟数据节，
汇编器+链接器 生成从地址0开始的代码跟数据节。然后链接器将他们的符号定义跟内存关联起来，并且重定位到这些节，在规划好内存后，并修改所有对这些符号的引用，引导他们指向这个内存位置。
并且将他们的内存的位置重新进行规划安排

字块集合体，然后 块儿中的程序代码跟数据信息，包含链接器跟加载器数据额机构 等  细腻系。编译器跟汇编器完成了大部分工作

7.3目标文件：
三种形式：
1 可重定位的目标文件：二进制代码跟数据，形式是 其他的可重定位的目标文件合并，并且创建可执行的目标文件
2 可执行  指的是可以直接复制到内存中并执行的过程
3 共享目标文件：可以被动态的加载进内存的目标文件

编译器 跟 汇编 生成 1跟3  然后 连接器生成的是2 

术语：目标模块：字节的序列。例如8个字节等组成的序列模式。
        目标文件：以文件形式存放在磁盘目标模块
在linux中可执行文件：a.out
第一个window是 PE的格式  
现代的x86=64用的是 elf格式 也就是说可连接可执行的格式

7.4 针对可重定位目标文件的具体信息:
ELF 的经典格式如下：
![[Pasted image 20241117091835.png]]
在ELF偷中有如下部分：16字节序列的字的大小跟自己顺序+链接器 语法分析解释目标文件信息+ELF头的大小+目标文件的类型+机器类型+节头部表的文件偏移等 
ELF跟 节头部表之间都是节具体及诶是：
1 .text:已经编译的程序的机器代码
2 .rodata:只读数据
3.data:已初始化的全局跟静态的c变量，局部变量c在运行的时候保存在栈中 ，不会出现在data 跟bss ，因为局部变量是针对局部存在 而不针对所有的内容
4 bss （better savve space）：未初始化的全局跟静态c变量  在目标文件中未初始化的变量不需要完全实际占据任何的磁盘空间内存中没初始化这一坨为0 

5  .symtab符号表，并且存放定义中的函数跟全局变量信息，每一个elf文件都有的内容，而不是必须只有显示-g参数才会显示的符号表，例外是程序员在这个当中使用了STRIP命令去掉了符号表
不同于编译器。这里只显示全局变量 而没有局部变量  。
因为链接器的目的就是为了借助全局变量的手把 所有的参数手拉手的链接到一起去
6 rel.text 这个重点是 当连接器把这个目标文件 已经设置好的文件跟其他文件拼凑到一起的时候，需要借助这里的内容。修改这些位置并执行对应的功能来完成这些内容，注意：全局变量需要修改，但是局部不可以
7 .rel.data: 任何已经初始化的全局变量，如果初始值是一个全局变量地址或者外部定义的函数地址，需要被修改
8 。debug ：调试符号表。这个表是真正调用-g的时候调用的
9 。line ：-g启动的时候才会得到 这个表。在原始的c行号跟text中机器指令的映射



7.5 符号跟符号表：
重定位的目标m都有的符号表。一共有三种不同的符号表；
1 m 定义并被其他模块引用全局符号，对应的是非静态的c函数
2 其他模块定义 m引用 外部符号
3 只被模块引用的局部符号，带有static的部分 在模块m的地方是可以随时看见但是其余模块不可以用
本地连接器符号“本地程序变量 这俩不同 因为 在symtab中不包含任何本地程序变相，不会对任何局部信息感兴趣 链接器只喜欢 全局信息
其中  针对如下模式：
在针对C 的static的定义  c中的static 揭示了 只会将范围限制在 局部信息中而不是全局信息中
其中针对函数F跟 函数g的局部信息变量的揭示，他们其实在连接器中的表示方式是不同的  
且身份是唯一的 这是最特殊的情况 

C语言中利用static的模块属于模块（源文件）私有的 他并不是公共的  不可以被其他的模块随意访问。也就是说，尽可能用static属性来做事情

符号表是汇编器组成的 。使用编译器输出到汇编语言.s文件中符号，symtab 包含elf符号表 
![[Pasted image 20241117094329.png]]
name 是字节便宜。指向字符串名字 
value 是地址  

对于可重定位目标文件而言：他们是有3个伪节存在的：主要是由section字段，
ABS：不该被重定位的符号
UNDEF未定义的符号  本模块引用但是定义在别的地方的符号
COMMON 还未被分配位置的未初始化的数据目标，
value 给出的connmon的对齐目标


工具介绍：GNU READELF策划给你续是查看目标文件内容的工具 主要针对查看elf文件内部的内容 
![[Pasted image 20241117095653.png]]
readelf 是一个专门用于分析二进制文件的工具类型跟内容 
直接就可以作为一个工具来分析linux中的elf文件的使用信息


![[Pasted image 20241117113052.png]]
这里面的value揭示了地址的起始位信息，而 后面上方的文章中的 
![[Pasted image 20241117113134.png]]
address揭示了他是输入那一个层  在address这一栏中解释了 
将其 利用gcc解释为 elf形式的
### 7.6 符号解析 ：
针对局部变量的解析“：
解析符号用的方式是讲起一一对应起来 ，并且可以引用定义在相同模块局部分号引用  
编译器只允许 每个模块局部分号中有一个定义 不可以有多个 
并且编译器对于局部变量而言只可以有用唯一的名字 既名字只能唯一
针对全局变量的解析：
1 当编译器遇到一个不在当前模块定义的时候 发给连接器 链接器自动搜索所有文件中并查找是否有这个信息，然后如果连接器在他们当中你都无法找到的haul，就输入一条错误消息（无法茶叶 并且终止
然后核心关键点在于 如何可以保障他们对多目标全局符号，多次定义的合理符号解析呢
这时候连接器规则如下：‘1要么就某种方法选择一个 定义并且扔掉其他的
                      2 要么就标志一个错误

`gcc -WALL 这个选项通常可以帮助程序人员发现一些隐藏的警告的问题，比如 链接器无法解析对foo的引用的时候，因为找不到文件引用它`
![[Pasted image 20241117114310.png]]
例如这些报错  其中原代码如下:
![[Pasted image 20241117114341.png]]
这些内容如上所示：
可见在此代码中。foo这个全局变量确实了定义 而且连接器无法再别的文件中找到他们 就胡标错 
这个可能会造成麻烦
在c++跟java中 是对连接器是允许进行重整的 
并且允许他们的符号发生重复变量的发生，

7.6.1 链接器解析多重定义全局符号
当 多个模块定义为同名全局符号 ，linux 内部会发生什么呢？
重点在于  在编译器 中  全局符号分为强符号或者弱符号。且规则如下：
定义：把函数跟已初始化的全局变量叫做强符号  没初始化的全局变量为弱符号

规则1 不允许有多个同名的强符号，
规则2 如果强 +多个弱 先选择强
规则3 如果弱同名 则 随机选

强弱符号的不同 差异可鞥导致漏洞的存在 （提权漏洞等存在）
可以利用此规则的差异 去人为恶意构造强符号或者弱符号 ，然后来使其库加载为恶意库，导致引入恶意软件的目的 
其中动态链接库劫持 dlls 也是之一
强弱变换符号。导致可能存在强弱变换为题，可能具有动态插桩设置的可能性存在

圣经就是圣经啊 
![[Pasted image 20241117170147.png]]
对于moudel2 中 而言 对于 main=1 来说 相对与 void main（）而言是同为强定义 
均为强定义 他会报错 

7.6.2 与静态库的链接
所有的编译系统提供机制：将所有的相关目标模块打包成一个单独的文件 称为静态库的文件 ，可以直接作为连接器的输入信号去执行他们 
支付至那些静态库里面被引用的文件

静态链接库的提出是为了 编译为独立的目标模块，并封装成一个单独的静态库文件的过程 ，然后 链接的时候 链接器只复制那些程序单独调用的模块

我不会复制所有的函数作为标准库的副本，我仅仅复制那些我在这段代码中所需要链接以及调用的函数类型 用他们来做为我的一种库来使用，由于不可更改性，所以这个库被称为静态库

注意 这是后与静态库的链接  分为如下几个步骤
1 分别创建 addvec.c  跟 multvec.c 将其转换为 .o形式  注意 此事后 在转换成 .o 后 需要认为提示一个   然后两个库分别是 加法 跟乘法  
2 需要 认为的提供一个 加法 乘法函数的 .h的 头文件 
![[Pasted image 20241118162011.png]]
源代码2 ：
![[Pasted image 20241118162023.png]]
将其进行连接
注意 我们此时的目的是 将其 也就是一个乘法函数，一个 加法函数 其中*X *y *z 三个为指针函数，而n代表了循环的次数
我们将 .c的文件变为.o的 ：
`gcc -c addvec.c multvec.c`
对于gcc 而言 -c 告诉 gcc 将源文件编译为 .o的目标文件。然后 并且后续提供惊天库连接他们 
`ar rcs 指定.a的文件  指定 。o 两个文件 并尝试把它们链接起来`
ar rcs 是一种创建跟管理静态库的命令，其中ar 是多个目标文件 打包成 的 一个单一的文件（.a）
供连接器使用，并且 常用语静态库，并且能让多个对象文件集合到一个库文件内，从而简化编译的过程

r c s 的含义如下：
1 r ：插入文件或者替换已存在的文件信息（replace）
2 c 创建归档文件：
3 s 创归档索引。链接器能更快速访问归档中的符号
这是一个人为打包静态库的过程 ：好比一个仓库，仓库当中存放很多已经人为定义好的函数，这个的作用是相当于把人为定义好的函数 放到一个库里。这些函数是自定义的放到库文件中集体存放出来的值
4 如何使用他们呢？
答案：
编写一个文件 来调用他们 。重点 ：注意其中调用他们的时候需要 在头文件中引用他们的来源，也就是告知程序我需要引用他们库中的内容 ，既为 xxx.h这个自定义的头文件中的内容 
因为系统并不知道 ，你认为拿来就用的自定义的函数 名称是否被定义，所以我们需要及时的告知他们

![[Pasted image 20241118163110.png]]
在这个当中我们引用了一个 自定义的头文件的值，并且 为vector,h的值，然后我们需要再vector.h中间放上 下面main函数中引用的addvec的信息 既x，y，z,2 分别代表什么函数 以及什么具体数值

所以此时 我们需要告知 系统 vector.h中是有 我们子啊这里面调用的 addvec这个函数的具体定义信息的  
所以我们创建了一个 名为 vector.h的头文件。其内部如下数据显示：
![[Pasted image 20241118163554.png]]
然后再敲以下命令：
`gcc -c main2.c`
`gcc -static -o prog2c main2.o ./libvector.a`

其中-c 不用解释，-static 代指它采用的是静态编译信心，而 ./libvector.a想当于告知他们我使用的是 这个静态库中的内容信息

![[Pasted image 20241118163800.png]]链接器如何使用静态库 来解析应用呢？
总结  
规则如下：链接器从左到右按照命令行的顺序进行解析：
一共有三个 集合 ：
集合1 E：存放了可冲定位目标文件 （即将被合成）
集合2 U： 未解析的符号文件
集合3 D：已定义的集合D
总结：我先去已经定义好的 集合中去找。如果能完全匹配 放到E 中 然后进行下一步连接
如果找不到，那么也就是部分匹配。那么就会去搜索新添加到链接库中的内容。观察是否跟我们需要的函数匹配。如果都不匹配，则直接报错或者任意函数 库中没有，则配不上，然后就直接报错

链接库的内容比较傻  
例如 lina.a 调用了LINB.a的函数  同时 linb.a又调用了linc.a的函数
就必须将他们穿起来然后 放置到命令行中，不可随意改变顺序
因为他是从左到右读取识别的 如果调换顺序 ，就会报错找不到 
我把他理解为 链接链条  它形成一个串串形式 前后关联首尾链接
#### 7.7 何为重定位 ？
当完成了符号解析后。连接器就可以把定位跟调用进行一一对应了 ，然后开始chog你大概哪位 步骤：
重定位 合并输入模块 。并且给每个符号分配运行的时候地址：
两步完成：
第一步： 重定位节跟符号定义： 合并同类项 将散落的节但是 特征相同的节合并到一起并且为他们分配好。他们应该分配的内存地址的内容，然后再将他们富裕符号   
这不得目的是让他们每条指令由唯一可以运行的内存地址
第二步：
重定位节中符号的引用：
链接器 修改对符号引用，让他们指向真正存放的地址中去这个重定位的目标模块 是称为重定位条目的地方。

#### 7.7.1重定位条目
汇编器生成这些东西的时候 并不知道 他们数据跟代码存放在内存最终那个位置 并不知道。也不知道 任何引用的额位置，所以 当汇编器引用他们的时候回程车一个重定位条目，来告知最终位置。
ELF定义的32位重定位模型中 里面重点关注的有：
1`R_x86_64_PC32`:是直接使用32位PC相对地址的引用，
2`R_x86_64_32`：是对32位绝对地址的引用 ，直接把其32位值作为有效地址
7.7.2 重定位符号的引用 ：
(1)重定位PC的相对引用
：依托于相对地址进行的环节  
（2）重定位PC的绝对引用是依托于绝对地址的进行 


#### 7.8 可执行 的目标文件
![[Pasted image 20241119162829.png]]
可执行目标文件  ELF头文件描述总体格式 八廓入口点 既程序执行第一条指令的具体地址 ，内容 以及行为逻辑
可执行文件是完全连接且已经被重定位的，不再需要rel节进行 操作行为
执行 
`objdump -p `来查看elf的程序文件头部表 行为 

程序的头部文件的问题揭示了，具体的 在可执行文件中连续的片是如何被映射到内存中对应地址中的位置上的 
具体 显示如下：
![[Pasted image 20241119163451.png]]
其中 off ：目标文件偏移  
      vaddr/paddr 内存地址 
       align 对齐要求
       filesz 目标文件中的段大小
       memsz 内存中的段大小
       flags 运行的时候的访问权限 
    ![[Pasted image 20241119163705.png]]
    对齐要求 是属于一种优化的方式。其针对于 off 跟 vaddr  要求跟 align 对齐要求进行取mod 并且取其中间的核心值，更像是一种规定了开头的请求

#### 7.9加载可执行目标文件 ：
`execve`任何的linux程序都可以通过调研跟着该函数来掉要哪个加载器 。架子啊其 将可执行目标内存的代码跟数据从磁盘复制到内促中，然后直接通过跳转到程序第一条指令入口点来运行此程序内容
这一部分  也就是将 其从磁盘加载到真实内存中的这一过程行为叫做加载 

代码段 +数据段+堆 调用malloc库增长  堆后面黑丝共享模块保留，用户栈是从最大的 合法用户地址  到较小的内存地址整张  ，从2的48次方到是为了内核的代码保留的内容 
![[Pasted image 20241119164938.png]]
这是他的具体的内部细节问题 
这段表示了 一个 系统文件汇总 具体的运行的时候内存长啥样也就是其内存映像是哪些个 


加载器运行的时候首先创建内存映像，创建后  将其可执行文件的片复制到代码跟数据段中，然后架子啊起跳转到程序入口点 _stat_的地址，

#### 7.10动态链接共享库 
为什么要设立动态链接共享库呢？因为静态链接共享库如果想保持随时随地最新的状态的话，必须要定期维护跟跟心  
问题二 ：当调用的重复的库函数的时候 会被重复复制 从而占用了大量的垃圾内存装置 
这是对内存系统资源的一个非常大的浪费，所以才会设立共享库。
共享库治理解决这些 ：
共享库 在运行跟加载的时候可以加载到任意的内存地址 并且在内存中跟程序连接起来。中间有个中转站是动态链接器，共享库中的 成为供你脏目标   ，linux 中用.so后缀表示 ，微软的操作应用了大量的共享库，且 成为 DLL动态链接库的东西 


共享库的共享方式：
方式一：对一一个库中的只有一个.so的文件而言，所有引用改库的 都可以去引用这个文件信息，相当于是个公交车 ，可以被很多人共同欣赏享用 ，他不会像静态库一样被复制或者被嵌入到内部使用
方式二：内存中 的共享库的.text副本可以被不同正运行的进程共享

现在生成共享库 ：
目标  根据addvec.c 跟 multvec.c来生成共享库 且调用编译器驱动你程序 ，故加入如下特殊的指令：
`gcc -shared -fpic -o libvector.so addvec.c multvec.c`
这个具体命令是 ：-shared :指定生成共享库 shared library  然后不是普通的可执行文件，这个共享库谁谁都可以用 属于“公交车”级别类型 其在 linux中的扩展名为 .so
-fpic 是生成无关位置的代码，PIC  共享库为了能保证正常工作 的话代码必须是位置无关的 

PIC在这里的作用是啥：
1 生成的共享库可以在任意的内存地址加载 ，不需要硬编码特定的内存地址中的内容
2 避免了地址冲突 纯属为了填写一段垃圾信息 来冒充合法的程序
第二篇文章中如下:
`gcc -o prog21 main2.c ./libvector.so`
这个语句当中 创立了呃借助动态链接的库 而生成的最终elf文件prog21 文件 ，其中所借鉴引用的额库内容是 ：`libvector.so`的内容 

动态链接库的做的事情如下：
重定位libc.so的文本和数据到某个内存段当中
重定位 到 内存段，并且 对所有的定义 符号引用功能 
当 多功能太链接控制传递给app。切当从这个时刻开始的话，共享库的位置就是固定且可行的 

7.11 从应用程序中 加载跟共享链接库
动态链接例子：
1 分发软件：微软利用共享库来分发软件更新 ，并且生成共享库的全新本部呢并且 链接
2 构建高性能的web服务器：生哦多功能太呢荣 以及 可以借助其改善

当有大数据的流量访问请求的时候 
可以通过将每个生成的动态内容构建到函数打包到共享库中的方式，来自web浏览器中的请求到达的时候，服务器动态链接适当的函数后直接调用他们，不用fork跟 execve行为  在子进程中运行他们，这样就函数会缓存到空间中

在linux 中 有个接口揭示了动态链接库的内容  
头文件为 ：`<dlfcn.h>`
这个 是 基础用法如下：
`void *dlopen(const char *filename,int flag)`
加载共享库 

`void *dlsym (void *handle ,const char *symbol`这个主要用于查找全局符号内容 

`int diclose(void *handle)`这个内容在于卸载共享库  等 
这个头文件的作用是  来保证 动态链接库的加载跟管理，让程序决定加载那个程序信息的值 
7.12 位置无关的代码：
共享库的目的值允许多个正在运行程序共享内存中相同的库代码，共享制度大家一起用 ，仓库在那里大家随意取用 这种模式，
多进程共享同一个仓库的方法：
方法一：每个公共想哭实现分配一个专用的地址空间片，然后要求加载器在这个地址加载共享库这种方法  会导致地址空间效率不高 并且难以管理，因为 有很多空间无效创建
如果创建了新的库必须赵栋寻你找其他空间，且对于每个系统而言，库在内存中的管理是不同的，
更优化的方法二：
编译器共享模块代码段，让他们可以加载到内存中任何位置但是不需要链接器修改，无限多个进程共享一个共享模块代码段的单一副本，每个进程依旧会有读写数据库

位置无关代码 PIC：加载但是不需要重定位的代码段PC相寻址编译这些，构造的时候静态链接重定位，
1 PIC的数据引用：全局变量的pic  
当内存中何处加载目标模块的话  数据段跟代码段的距离不变，且距离是个运行的时候常量 ，不管在内存中的哪里都无所谓 
重点在于偏移量是固定的 也就是说我们在已知偏移量的前提下 固定距离已知。我们只需要建立一个GOT全局编译量表，其报名所开始的绝对地址，也就是 他的开始的地址。在此基础上直接加入便宜的固定距离即可 

这个GOT指的是全局屁啊你用量表。并且引入一个8字节的条目系统 

2：PIC函数调用：
GNU编译系统采用了延迟绑定的技术来 解决 预测函数调用的运行的时候的地址  ：
要延迟绑定：
其中延迟绑定是通过俩数据库之间的复杂的交互实现。链各个数据库为 ：GOT跟过程连接表（PLT）：
如果一个目标调用的函数库的话 马上会生成自己的GOT跟PLT机制。且 GOT作为数据段 PLT作为代码段的一部分执行并且实现

PIT跟GOT 架子啊的过程中费劲点 第二次的时候就类似自动标记好了相关的地址位置，直接定位到地址信息即可

7.13库打桩机制：
linux 的机制，截获对共享函数的调用 取而代之执行自己的代码，最总对某个特殊库函数调用此时 ，替换成我的机制（崔宝江老师的团队！）

基本思想： 给定义一个需要打桩的目标函数，并且创建一个包装函数，这个包装函数作为复制品且与这个 目标函数一模一样然后去欺骗系统调用设计好的包装函数，后 执行自己的逻辑，然后再返回调用目标函数，将目标函数返回值给调用者 

其中 代码段逻辑如下：



![[Pasted image 20241122112914.png]]
原函数代码逻辑是借助malloc 跟free动态分配并且向栈中人为的插入地址 ，然后 动态分配跟存储地址
然后
我们现在要自定义一个 mymalloc.c的程序来插桩 人为取代这个函数地址的范围，从而造成重写malloc 中的 malloc 分配跟 free目的，重写的目的是为了将里面的地址释放出来，查看具体的地址内容逻辑。
在预定义 malloc的时候这是 malloc .h 中的 冲顶万一标准内存分配跟 释放操作，主要用于观察调试内存中的指针地址的具体数值 

具体内容解析 
`#define malloc(size) my malloc(size)`
`#define free(ptr) myfree(ptr)`
这个是 宏重定义,目的是将所有调用malloc 跟free的地方替换为 my malloc 跟myfree 
且为透明替换，并且不需要修改malloc的代码 逻辑，会自动替换为定义的函数 
不修改原始代码的情况下 对所有的动态内存加入额外的逻辑框架问题，同时为了项目引入统一的内存管理缺口 便于调试跟优化
再然后声明了函数 malloc 的函数跟myfree 逻辑函数 
然后提前定义了内容，具体内容是啥别的文件中会有定义 

目的就是重定义跟重写内容逻辑 
在宏的重定义中 ，可以借此修改大型代码库中的内容并且做个无痛的替换 ，这就是所谓的重定义内容 

而在主函数中 malloc引入了一个 malloc的指针掉要哪个动态内存，并且释放内存的行为，我们额外建立一个插桩代用的目标函数，然后写入逻辑如下 ：
```
#ifdef COMPILETIME 
#include<stdio.h>
#include<malloc.h>
void *mymalloc(size_t size) 
{ void *ptr=malloc(size);
printf("malloc(%d)=%p\n",(int)size,ptr);
return ptr;
}
void myfree(void *ptr)
{ free(ptr);
printf("free(%p)\n",ptr); 
} 
#endif
```

其中引入了一个 机制叫做 调试机制 ‘
在 `#ifdef`到 `#endif`这是宏预设机制 也就是如果 程序中定义了 这个COMPILETIME这个程序，就执行下面这段代码，否则的话就直接跳过 
这么设置的目的是为了调试这段带阿妈机制 
这段的逻辑是 打印出来具体的malloc引用的大小跟 函数的地址空间，并且打印出来以供查询查验

我们在命令行中输入：
`gcc -DCOMPILETIME -c mymalloc.c`
具体各部分的命令解析：
1 gcc 是编译器命令 
2 -D ：用于编译的时候宏定义  相当于人为输入一个宏参数，一般是用来触发#ifdef 跟 # endif 的 。也就是测试用例的
3 -c ：进进行编译 也就是 只把他们编译成.o 的形式但是不会生成可执行文件，因为 我们要自己定义一个malloc函数 进行动态插桩，但是定义的部分还是存在的 

`gcc -I. -o intc int.c mymalloc.o`
将其进行连接行为，然后 -I指示了他的连接的文件要从哪里去找，这个.告诉编译器我要在 当前目录下寻找文件 

#### 7.13.2链接的时候打桩：
结构解读：
![[Pasted image 20241122162225.png]]

整体是一个动态链接插桩实现：主要目的是运行时候替换标准库中的malloc 跟free函数，并且每次分配的时候打印相关信息

1 对于 `void *_real_malloc(size_t size)`
跟 `void __real_free(void *ptr)`
这个声明了原始的malloc 跟free

其中关键带你在于 _real_malloc跟 __real_free是gcc链接器包装的  功能 
她是解释了调用标准的 库中真正的malloc 跟free 即使重定义了他们

2 `void *wrap_malloc(size_t size)`
自定义的malloc函数 用的是_wrap_malloc名称
、跟内存分配的指针类型 
返回分配的指针类型 

3 `void __wrap_free(void *ptr)`
自定义的free包装函数，使用`_wrap_free`名称
进行执行实际的内存释放功能机制


针对gcc链接包装的机制：
gcc中允许开发者重写特定函数来支持插桩或者自定义行为 发生
关键点：
1 `__wrap_<fuction>`是包装函数的命名规则 替代标准函数也就是所喂 的插桩后的函数
2`__real_<fuction>`对原始函数的调用，包装函数中保留标准行为
如何启用包装机制 ：
1 --Wl ，--wrap=<fuction>这个告诉机器 我用的包装函数是fuction里面的内容  
并且告诉链接器 我的所有对function 的调用 
2 调用原始函数的机制__wrap_malloc这个代用的是原始函数 指的是原始函数行为 


借助 realmalloc 可以 保留原始函数的行为的同时 但是包装代码并不会改变程序逻辑

### 7.13.3运行的时候打桩
编译的时候打桩要求能访问源代码  连接到时候打桩是可以访问程序可重定位的文件，另外一个机制 是访问可执行的目标文件细腻系，运行的时候打桩 
基于动态链接器的 LD_PRELOAD环境变量 
比如如下程序：



完结  动态链接莫名报错

