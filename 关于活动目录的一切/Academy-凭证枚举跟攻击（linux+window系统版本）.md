前提条件 ：在域中已经把脚跟站稳后“
加入域的主机上获取到 用户明文密码  ntlm密码哈希或者system的访问权限的问题：


在linux中：已知的凭据信息 ：user=forend password =Klmcargo2
## 第一种工具：Crackmapexec 

![[Pasted image 20250115104008.png]]他的帮助文档是这样的  看到 可以跟 在最后一栏 protocols（协议）中可以获取到这么多个协议信息跟内容信息
如果想查看某个具体的协议细节 以及如何在其下面使用的可以这么使用：
以smb协议为例 输入：
`crackmapexec smb --help `
可以看到：
![[Pasted image 20250115105120.png]]
我们关心的只有 ：
1 username:
2 password：
3 ip
4 --user
5 --loggendon :
因为我们目的是枚举这些用户密码组等信息 为的是进一步获取最高权限 来搜集并获取相关信息内容 
我们已知某个域用户的username 但是如何通过它联迪阿楚所有与用户的名字呢 ？
所以 现在使用smb 中的 --users 来发觉 
此时的基础信息如下：
ssh链接到接入对方目的内网的肉鸽为：

![[Pasted image 20250115110233.png]]
也就是所在网段为：172.16.5.225网段的内容  
我们前期得到情报得知目标主机位 172.16.5.5这台主机的内容 ：
所以编辑命令如下：
这是命令：
![[Pasted image 20250115212111.png]]
![[Pasted image 20250115212049.png]]
结果如上述所示，可以看到我们在这里能拿到yixiuge诶想你想  具体在哪个与 是谁 设呢末端偶 以及可能存在的用户名  等等  
对方可能设置的防御值：会在 badpwd count 处设置选项 来尝试进行拦截等 ， 如果尝试失败可能跟此属性的设置等因素有关 
![[Pasted image 20250115212317.png]]
https://learn.microsoft.com/en-us/windows/win32/adschema/a-badpwdcount
其中的badpwd count ： 这个是错误密码尝试次数 来告诉咱们这个是可能性最大的信息点     如果这个数字超过零 的时候就要谨慎 因为 证明这个密码可能是错误密码，防止尝试次数过多导致误封 


信息搜集点二  ：
`--group`的魅力
![[Pasted image 20250115212621.png]]
列出了可能存在的所有组的信息，其中member count 解释了组内可能得成员数的具体指 


`--loggendon-users`
其中pwn3d！的含义是这台机器的这个凭证是最高管理员权限，Pwn3d!  代表这个机器可以做跳板机 


![[Pasted image 20250115220034.png]]
信息搜集点三  
针对于主机的shared 级别：
![[Pasted image 20250115221726.png]]

![[Pasted image 20250115222025.png]]
![[Pasted image 20250115222511.png]]
 如果一个smb 是true的话证明 他启用了 smb协议签名 其对每个数据包包含数字签名信息， 有效预防中间人攻击 MITM  的过程  
### 借助 SMBMAP来帮咱们做凭据信息搜集
如果 smbv1 是false ，
smbv1 是一个老旧大量漏洞协议，比如可能会被勒索病毒攻击 ，可能产生大量可能得攻击面 
关于 SMBmap的一切 
什么是smbmap?  
定义：
是把smb协议当做地图一样枚举的一个工具信息 ，其中 smbmap 的支持操作系统是 samba  
而samba 是一个用来执行免费 smb协议的工具 ，主要作用是使用smb协议共享网络中文件的信息内容
对于samba：
1 将其旗下的file文件目录挂载为文件samba 程序内容信息 ，并且挂载为文件结构的一部分，也可用smbclient 来读取共享，执行标准命令行的ftp程序 
只能访问 此目录的权限，并不能访问 同类别下的其他人的权限信息  ，不可跨目录访问 
对于smb协议：
smb协议是微软分布式文件系统实现的基础 
分布式文件系统：不同的位置的信息分配到同一个根目录下 的分布式文件系统 
多个不同位置的共享信息逻辑地
分布在各个地方的文件的系统信息最终会 汇总到一个逻辑树下 
尽管他们物理上是分散的 ，但是最终汇总起来以一颗树的样式呈现上去
如何利用smbmap查看共享信息内容？
![[Pasted image 20250119182836.png]]
这里smb 的默认端口号为445 记住了 在smbmap -h的帮助文档信息中 
![[Pasted image 20250119184137.png]]
在上述命令中通过此命令 弹出的信息中查看到，我们smb共享默认的 所在的域环境跟工作组的内容 
在 smbmap中 的帮助中提示我们需要指定具体域内容不然默认是workspaced 显然 ，此场景中的域名称不是workspaces
我们的目的是使用smbmap在 域中搜集足够共享文件的信息内容 
具体查看帮助文档后：
![[Pasted image 20250119184340.png]]
其中-u -p 已知 -d 未知  上述查询后已知 所以采用第一条命令
注意 在设置 crackmapexec 中透露出了三条信息 ：
第一条：所在工作组的名称  
第二条是所在域中的用户名 跟密码。

![[Pasted image 20250119184507.png]]
至此执行smb map命令 
命令执行后如下显示信息“

![[Pasted image 20250119205219.png]]
类似信息 点透露出来的是 具体目录的具体 用户权限问题 
且-R 是递归扫描所有的目录并且展示出来  如果-r是不用递归扫描可以自定义指定具体目录内容即可
第三个工具 ：
rpclient : 链接：
https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html
配合smbma而搭建而成的工具信息 负责搜集数据信息内容并且做一个分析 
基础设置  ：可以无密码链接再仅仅知道用户名的情况下进行链接 
且对于 rpclient而言提供一种佚名访问的模式即在 空用户名的前提下进行佚![[Pasted image 20250119205823.png]]
名访问即可 

在其man文档中有-U 跟-N 这个选项内容 使用即可 
-U 提供usrname 在首次可以尝试它的空名字 即无名高层登录 -N 一无密码服务机制
即为佚名访问 
在man 手册中可以找到一些关键的函数信息 ，并且观察到函数的 应用
在rpcclient中首先使用了  rpcclient 的魅力无穷值得探索
可以知道的是 当我们进入这个前 如果对方开启了这个服务 务必会涉及到关于
`rpcclient -U "" -N ip地址`
建立连接后采用各种函数名称进行枚举以及详细的信息搜集


### 与python的巧妙联系 ：
关于 impacket 与域相关内容 
其包含有两个内容 
1https://github.com/fortra/impacket/blob/master/examples/wmiexec.py
2
https://github.com/fortra/impacket/blob/master/examples/psexec.py
使用场景：当我们已经获取到用户hash（通过responder）后并且获取到最终密码 ：transporter@4
我们想直接将用户提升到本地管理员级别  ，该如何做呢？

第一步：执行脚本：通过这两个脚本进行执行 试图利用随机命名的可执行文件上传到ADMIN$主机上共享来创建远程的服务内容，然后通过rpc注册该服务 建立后通过管道可进行 ，并且提供远程shell 
脚本所需内容：
![[Pasted image 20250120091915.png]]
前置条件中已知username=wley 。password=`transporter@4`
所在域：inlanefreight.local 
payload ：`inlanefreight.local/wley:'transporter@4'@172.16.5.125`
使用上述这俩的时候如果对方能开启 rpc 的通道的话并且允许此项运行的话可以直接执行其脚本内容
共同点在于沃恩需要本地管理员权限的用户凭据信息内容并且合理的使用他们

其中经历多次尝试即可 ，二者的区别在于
1 psexec.py是一种随机命名可执行问价你上传到ADMIN$的目标主机上共享创建远程服务并进行链接的内容逻辑，家里后 提供 wscm 一样的system交互远程  基于 sysinternals psexec 可执行文件进行克隆并且上传 ，可以直接执行脚本内容并且将内容上传到服务器端的过程
psexec是一种轻量级的telent替代品 用户通过这种软件来建立远程沟通的桥梁 ，
2wmiexec.py则相对来说较弱一些，他主要是应用了弱项shell半shell建立链接，且交互性没有psexec.py那么强 注意其并不会向其他的目标主机中放入儿呢好的可执行文件 ，但是会触发现代的防病毒跟 edr等系统 并且会生成日志为“https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688
4688的日志信息，因为是半交互式shell并不是全交互式shell的缘故。
可以通过4688日志看到创建了一个cmd.exe程序 并且易被发现
这是由于wmi性质决定的 ：wmi：https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page
利用远程处理脚本对象的语言而创建并使用的一种脚本，在这种情况下链接上去的不是system权限而是本用户权限的信息， 但是相对于上一种而言更加的隐蔽 因为不用在目标系统平台创建任何的用户内容
由于wmici.py的普适性 从而导致了这种工具应该被常见的使用的特性
判断是否对方开启防火墙后再去使用 ，这个只有对方开启端口并且并没配置相关信息的时候才可以去用 




工具三：windapsearch.py:https://github.com/ropnop/windapsearch
![[Pasted image 20250120095106.png]]
用途：进行ldap等枚举工作 
关注这么几个选项 ：
1 --da 枚举管理员成员 
2 -PU 查找特权的用户 
![[Pasted image 20250120100332.png]]
目标：枚举相关的管理员用户，查看管理员用户组的信息：

payload1：`python3 windapsearch.py --dc-ip xxxx.xx.xx.xx -u username@包含的域网络系统全程 -p 密码 --da`![[Pasted image 20250120100605.png]]
利用 ：![[Pasted image 20250120110225.png]]

工具四 体系4 ：Bloodhound 工具篇章
bloodhound 提取器 ：
https://github.com/dirkjanm/BloodHound.py
主要作用是 识别相关信息 并且创建图形化的 域攻击路径的显现，
并且 将其问题可视化华丽  使用图论第二个攻击方式检测  
工具的构成
第一部分收集先关bloodhound 相关信息  第二部分是 将其使用图形化的方式展示出来

1 c#编写的window系统的 与bloodhonud的收集器相关的内容 
https://github.com/SpecterOps/BloodHound-Legacy/tree/master/Collectors
2 基于linux 编写的 bloodhound.py提取器 

第二部分是 bloodhound 的gui图像，并且将其图形化的展现在屏幕中 

Cyber 是查询的基本语言 
可以借助攻击主机去 用python 来收集他们 

![[Pasted image 20250120112016.png]]
思路如下  开启bloodhound-python 并且输入对应的用户名密码 -ns 链接到对应的服务器 也就是目标ip 地址值 标记好要搜集的域信息 -d 域 的全部的一直信息 -c 表示这 搜集的内容 all 表示所有 包含于
![[Pasted image 20250120112127.png]]
这里的all表示所有这些类型 执行后如下 ：
会生成一个![[Pasted image 20250120112248.png]]
说明数据已经搜集完毕 现在我们要做的是将他们在bloodhound 中以一种图形化的方式展现出来
将其搜集到的数据信息打包成压缩包.zip:

