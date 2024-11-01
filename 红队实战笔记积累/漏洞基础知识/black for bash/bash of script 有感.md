笔记整理 ：
第一本全英文技术书籍能否成功阅读完成？ 敬请期待 
1环境变量 的查看
`env`查看当前环境中所有存在的环境变量的值
![[Pasted image 20240808224332.png]]
2 查看指定的环境变量
这些大写字符中 就是可以人呢为指定环境变量的值  如何指定他们呢 
`echo ${pwd}` 上述PWD 这一行 
![[Pasted image 20240808224456.png]]
![[Pasted image 20240808224725.png]]
某些基础的表单如上述所示 
对于mkdir而言 由 
1`mkdir directory1`
2 `mkdir directory1 directory2`
3 mkdir 命令允许创造两个 目录连这些  且 无法创建于之前目录相同的目录文章
4 `ps -e -f ` 或者是 `ps -ef`
![[Pasted image 20240811172552.png]]
显示出命令行内容  以及操作系统进程的分析   当前执行的任务流派问题
显示出占用磁盘的大小空间是多少
5 `df --human-readable`
这条命令解释了磁盘数据大小
![[Pasted image 20240811172840.png]]
6这个命令揭示了磁盘的数据 以及数据占领的大小是多少的问题 

bash脚本的原理：
1bash脚本不是官方语言 ，但是这里解释了 所有 的知道 https://google.github.io/styleguide/shellguide.html
the shebang line 
对于每一个语言 我们需要特定的符号让 编译器知道我们是采用了bash脚本的用法 也就是告诉编译器我们使用的是bash语言 
这个叫做 头文件  
`# /bin/bash`这句话解释了什么是bash 脚本这样 就能告诉 编译器我们是使用的bash脚本呢而不是别的东西 
如果你 的bash脚本是跟ruby或者是跟python叫哦本 一样 使用的话，他的头文件可能变成这个样子：
`#!/usr/bin/env bash`
告诉翻译器的我们也是用的bash
在渗透测试过程中，当我们需要调用bash脚本的时候他可能并不在默认位置或者说是 他们的位置可能采用特别的方法去寻找待定的位置 ，但是在这本书中磨人的是  # /bin/bash这个位置 

`#!/bin/bash -x`这个选项加入后  我们将debug 各种错误参数信息输出到 目录里面 ，，就如同这样
![[Pasted image 20240811174241.png]]
这就会把错误输出到屏幕上 

Variables 变量:
1数字  开头可以使下划线 ，但是开头不能呢格式数字 不能有空格
2变量的使用方法：
  (1 )${ }放置变量 的名字
  book ="black hat bash "
  自定义变量的内容
  echo "this book is name is ${book}"
  使用变量的时候  使用 的时候 配合 ${内部是变量自定义的代号也就是变量的值}
  (2) $( )放置具体的命令
  例如：$(具体的想执行的命令)
（3）单双引号的细节
单引号的时候是这样的
![[Pasted image 20240823213304.png]]
打印的是命令的内容 即为单引号内部写的啥会原封不动的打印出来

而双引号的打印的内容是这样的：
![[Pasted image 20240823213351.png]]
会将其作为一个特定的值也就是 相当于你在命令行中输入了对应的内容来进行操作 

二  Unassinging varialbles
取消分配变量
使用的是 unset

三 scoping variable  限定变量范围
局部变量 local +变量名 
设定函数 是 
设定函数名(){

}

使用函数 直接使用 啥都不用带直接用 

全局变量中的 大写仅仅是为了跟普通变量做个区分

四 Arithmetic  算术运算符 

列表如下：
常用的 arithmetic operators 列表如下：

| +   | Addition                           |
| --- | ---------------------------------- |
| -   | subtraction                        |
| *   | multiplication                     |
| /   | division                           |
| %   | modulo                             |
| +=  | incrementing（增值） by a constant（常数） |
| -=  | decrementing （减少）by a constant（常数） |
规则如下 ：
1 利用let 来告诉系统这个是个包含算术运算符号的东西 需要进行算术运算的数字 
![[Pasted image 20240824095350.png]]
可见如果没有let的预知 的话  系统是将不认识这个 会原封不动打印出来这个值 
2 用美元符号+双括号的形式表示 
3 用expr表示 
![[Pasted image 20240824100005.png]]关于数组：
数组设置中 有
![[Pasted image 20240824101205.png]]

1注意设置数组的时候用的是 =( )具体指
2echo `"${变量名[0]}"`  `[ 内部是序号也就是次序是从零开始的 ]`
3可以单独的 取消数组中的某些值 比如 unset 数组名字`[序号]`
4可以通过 数组名[序号] 然后="具体数值"来修改具体在某个位置的数字 位置 

五 Steams 数据流
定义：文件跟环境交互的数据流  
不管是他内置的还是 自己的  他是一种数据通道的体现 学术体现 
其中对于bash 而言有 以下三种表现形式 ：

| name                     | description（描述） | 文件描述的数字 |
| ------------------------ | --------------- | ------- |
| Standard input (stdin)   | 输入该程序的数据        | 0       |
| Standard output (stdout) | 输出的数据           | 1       |
| Standard Error(stderr)   | 报错信息            | 2       |

![[Pasted image 20240825213309.png]]

重点注意  
& 是将数据发送到后台的命令
;是 此行命令结束 相当于平常的回车键 结束并执行 
| 是管道 ||或
&&与 
;;全剧终 

关于 重定向 

常用的有以下几个 

| operator   | description                                                        |
| ---------- | ------------------------------------------------------------------ |
| >          | stdout to a file                                                   |
| >>         | stdout to a file by appending(添加) it to the existing content(现有内容) |
| &> 或者>&    | stdout and stderr to a file                                        |
| &>>附加到末尾的值 | 添加到末尾                                                              |
| <          | 反向重定向  跟着大于号的流向走                                                   |
| <          | 附加的值                                                               |
| \|         | 管道 将输出传送的一个 工具                                                     |
|            |                                                                    |
如果 在一个文件中使用 >而不是>> 将会被完全覆盖  
如果一个写好的文件上面用的是 >>相当于附加到最后一行，然后>代表的含义是覆盖整个文件 产生新的值
例如 ：
`ls -l / &>stdout_and_stderr.txt`
这种情况是将ls -l 的输出并且 将所有的错误值输出到 一个文件内并查看  
与上面1 2 3 数据流的联动 

将脚本输出的数据流 进行分离 也就是输出分散到一个数据流中，错误又输出到另一个数据流中，即脚本可以这么写 借助1 表示的是输出流 2表示的是错误流  0表示的是输入流

`ls -l / 1>stdout.txt 2>stderr.txt`

注意此时：1 是写到大于号前面的内容 的 

多行重定向：
利用EOF   他们中间是多行重定向的命令 
例如：

![[Pasted image 20240826174415.png]]
请注意两行EOF发生的情况以及标准是啥 



利用他们可以干什么  ：
1 当发生错误 并且没输出到屏幕上 也就是实际上发生错误了，但是我们看不到他
并没有输出到screens 屏幕上的话 ，可以通过定义错误日志 并且查看错误日志的内容来查看最终结果 


借助脚本进行简单的交互输出  
目标是 利用脚本 去进行ping 网站并且输出到屏幕上 
	核心是:`ping xxx.com`这个命令 
	我们希望 xxx.com这个命令是客户自己输入的命令  
```
#！/bin/bash
#注意此时的0 1 2 代表的是输入的第0号位置 1号位置 2号位置的值 其中以空格作为分界线进行分解
script_name="${0}"
website="${1}"
company_name="${2}"
echo "this geshi  scriptname website company_name"
echo "please input you script name ${script_name}"
echo "please input you saomiao d web geshi shi xxx.com ${website}"
echo "please wait..."
echo "please input you company name:${company_name}
ping "${website}"
```
访问所有的参数 ：$@   显示访问的参数 的数目总数 $#
参数的人话：参数的人话就是，使用者使用这个脚本的时候与代码进行交互的数目的多少 
例如：
![[Pasted image 20240826210329.png]]


五 输入交互
使用read 来尝试与用户产生交互 既能弹出一些东西 
![[Pasted image 20240826211049.png]]
1这个 -r后是防止他被解释称转义字符 导致的  一系列问题 例如\\n中国的无法读取等问题 
2注意 read -r 后的直接加变量名字 并不需要加任何的特殊字符的形式

退出状态代码 
一 exit status codes
显示是否执行命令成功  的一个脚本   
ps 对于状态码而言  如果显示数字 是0---255之间有特殊含义 
0 表示 执行成功
1表示失败 
126表示 这个命令发现 也就是有这个命令 但是无法执行 
127表示的是 命令未发现     
这是不同的返回的函数代表的不同的 指的含义  
bash中通常用的是 `$?`
进行错误代码显示  ，例如 脚本如下图
![[Pasted image 20240826212548.png]]

1 这个报错信息如下   code 1代表执行错误    code 0 代表执行成功 
2 /dev/null表示的是 一个空文件，若你只是想验证这个输出是否正确 并不想真的执行这个  
就可以采用 借助linux 中的这个 文件内容信息 
3使用/dev/null 的这个路径 的时候要小心 因为他可能会错过一些真的错误的选项内容 
4使用场景  当 利用bash 下载1gb的文件的时候 ，不知道对方是否已经下载 ，可以考虑这么进行测试一下 根据返回代码来决定是否下载

## 第二章 高级bash的使用 ：

bash environment for penetration testing
一 测试操作员 
