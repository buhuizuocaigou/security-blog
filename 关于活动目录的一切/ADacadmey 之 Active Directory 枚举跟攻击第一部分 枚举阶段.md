目标：熟练应用工具集以及手动枚举套路操作 

https://academy.hackthebox.com/module/143/section/1262

模拟真实世界中指定 CRT交战规则界定的文档进行的仿真模拟训练跟练习：

### 一 ：外部侦查跟枚举 

我们该侦查什么  ：
![[Pasted image 20241129103924.png]]

1 关于AS：路由策略 是AS控制的IP的空间列表以及链接其他的AS的信息，路由报到正确的网络 ，AS使用的是bgp：分布在不同公司的网路系统将通过一个核心的数据库串联起来，这个数据库组成的 AS路由策略信息。
##### IP地址空间 ：
AS是管理ip地址空间的一个控制器，的装置，且数据包到达另外一个AS装置 
一个AS控制一群IP快  不同的AS控制的不同的IP块儿组成了不同的抵御，也就构成了公司集团的重要组成部分 
AS会都有一个唯一的编号ASN 编号用于区分不同ASD之间的区别 
AS与AS之间链接的协议 成为BGP协议 的数据信息，他是在路由表中的数据信息模式跟模块 
如果不给出定义的具体的下一条以及网上的具体路径内容的话，IP数据包会随机反弹 导致 让驾驶员猜测干的啥 内容 

我们主要搜集啥信息：

| 资源                             | 内容                                                                                                          |
| ------------------------------ | ----------------------------------------------------------------------------------------------------------- |
| ASN/IP registrars              | [IANA](https://www.iana.org/)、美洲的[arin ](https://www.arin.net/)欧洲的[RIPE](https://www.ripe.net/)  BGPTOOLKIT |
| Domain Registrars DNS          | 针对dns 的清楚记录信息 ：包含有Domaintools 、PTRArchive、ICANN                                                             |
| Social Media                   | 搜索社媒 比如 linkdin 的facebook等各种信息来源                                                                            |
| Public-Facing Company websites | 公司信息 新闻文章等                                                                                                  |
| Cloud &dev storage spaces      | Github AWSs3 degn  以及                                                                                       |
| 资料来源 例如电邮的泄露等信息的发生             | [使用HaveIBeenPwned](https://haveibeenpwned.com/)                                                             |
|                                | https://www.dehashed.com/                                                                                   |
搜索 互联网那个的ip信息：
https://he.net/ 中的bgp-toolkit home  查询所属的ip信息等内容  
![[Pasted image 20241129152316.png]]
例如中国再保险等相关公司内容 ：
目的是确定范围内的界定 的相关内容 ，总归纳 防止逃离界定之外的测试内容  
在渗透测试的时候 注意这一个点 

![[Pasted image 20241129152640.png]]
做这些的目的是为了明确范围化 并且被动的搜集相关信息内容 以及综合信息团体评价 


DNS：
针对DNS的测试 ：
https://whois.domaintools.com/grammarly.com
这个网站的信息搜集相关dns的信息域名删选 


关于一些招聘信息的列表 不能忽视的信息媒介跟输入的标准 
https://trufflesecurity.com/trufflehog
关于github泄露信息的网站凭据信息泄露的可能存在的店 
实战 对拳头公司的扫描 
：
总体的枚举原则：
正在寻找良好的目标并且 寻找相关路径信息

https://viewdns.info/
这是一个查找防火墙的关键信息 以及dns相关信息来源  
![[Pasted image 20241129163055.png]]
此时也可使用kali中的 
`nslookup工具来查找对应域名相关信息`
![[Pasted image 20241129163853.png]]
对应的相关信息如下 ：
顺着往下找 ，此时我们已经知道他的ip地址以及可能包含的域名名称等具体信息，然后像进一步利用的话 就 在google搜索如下：
`filetype:pdf inurl:inxxxx.com`
这个 filetype :是告诉谷歌查找所有可能得pdf  inurl 是告诉谷歌必须包含有 后面这个网络字段名称，至此 搜索到如下信息点：
![[Pasted image 20241129164625.png]]
https://www.inlanefreight.com/wp-content/uploads/2020/09/goals.pdf
得到pdf 一篇 

http://blog.inlanefreight.com/wp-content/uploads/2022/04/Q2-To-Do.pdf
得到第二篇pdf 泄露信息如下 ：
![[Pasted image 20241129164758.png]]
此时注意 查看完pdf 查看可能包含的email邮箱的地址
![[Pasted image 20241129165209.png]]
查找电子邮件信息 并且找到包含电子邮件的店 ：
对于linken页面的用户名搜集 ：
https://github.com/initstring/linkedin2username
关于可能泄露的用户凭证的信息搜集：

https://dehashed.com/
一切目的是找到一组泄露在外部的可能的凭据信息，并且根据找到的凭据信息搞事情 

### 针对与域内的信息搜集以及需求：
常见的客户可能对漏洞信息的要求:
![[Pasted image 20241130104031.png]]
对于当下的需求是：
![[Pasted image 20241130104103.png]]


当前阶段搜集任务 ：
1 枚举内部网络 识别主机关键服务跟潜在立足捷径
2 包括主动+被动措施来识别可能进一步访问的客户、主机、漏洞
3 遇到任何发现  
进行黑盒渗透 等  ，或者接触  无线访问  假设是黑盒的数据点 

我们搜集数据关键信息点在哪里：
1 

| 数据点                           | 描述                                           |
| ----------------------------- | -------------------------------------------- |
| AD Users                      | 尝试枚举可能作为password 爆破的关键用户池                    |
| AD Joined Computers           | 包括AD domian 文件服务器 sql服务器 web服务器，exchange服务器等 |
| key services                  | kerberos Netbios LDAP dns                    |
| vulneralbe hosts and servcioe | 其他的任何服务                                      |

补充点 ：NETBIOS是啥 ：这个是基本的输入输出的网络服务系统，能用于早起的 IBM 构建LAN 也就是局域网通信系统而成立的网络机制 
1980年产生  
NETbios 中以 ncb的形式请求网络控制块等内容 其中 在会话层 中提供服务

为了在庞大的系统中得到合理的立足点 跟 落脚点 我们需要按照一个计划进行逐步解决  
自己 执行 发现适合自己的呃方法  
尝试不同的解决方法  最终生成自己独一无二的技战术体系 

思路如下 ：首先枚举在网络中所有的主机 ，然后去了解每个主机更多的细节 例如序列号等 
再然后回到第一步，在停下来筛选并且整理所获得信息 最终拿到数据的凭据点 
### 第一步：识别主机 ：
采用 两个工具来识别网络：
1 wireshark   2 tcpdump  可以捕获那些网络流量 ，
 为什么要这么做？
 答案：因为 当我们想首先了解这个主机具体信息的时候可以借此去进一步探测 主机发出来的相关数据包来了解内容 此项内容针对黑盒进行并开展，由于不知道对方的ip等进一步信息 只能从捕获流量包开始 
 此时 场景为 进行黑盒渗透测试 并且根据wiersahrk 跟 tcpdump来捕获数据信息 
 此时的 信息点：ssh 账号 ：htb-student  ip地址：10.129.222.68 ip密码：HTB_@cademy_stdnt!
进入ssh 查看信息点为：![[Pasted image 20241201144923.png]]

在ssh选项中开启wireshark 侦听变量 
`sudo -E wireshark`为啥开启-E 呢  答案是 因为-E 是选项提示出来 不改变环境变量的操作 也就是说保存当前环境变量内容，所做操作是临时改变 ，并不是永久变化 既不会永久影响环境变量内容
有wiresheark 用wireshark 目的是搜集到一些流量包信息 
那么搜集那些流量包 为什么要抓取重点关注这些呢？
流量包有：1 ARP的请求跟回复流量包 ：
什么是ARP流量包 ：当想向另一个节点发送IPV4但是不知道 节点的但是上不知道的节点的mac地址的时候需要使用ARP 请求  ，包含于 IPv4相同的链路层地址 ，
https://en.wikipedia.org/wiki/Address_Resolution_Protocol
二 ：当无法用图形wireshark获取信息的话 可以采用  tcpdump ，net-creds 跟NetMiner来执行  
可以先从tcpdump捕获后 传输到另外一台攻击机上 并且传输到另外一台主机上 并且wireshark打开他们 
工具 ：1 https://github.com/DanMcInerney/net-creds  
      2：https://www.netminer.com/en/product/netminer.php
      3 kali 自带tcpdump 
      上述为在linux 中的工具信息 ，但是如果存在于window的话 可以采用的是，pktmon 具体官网如下;
      内置的网络诊断工具
      存在于window系列 
      
      https://learn.microsoft.com/en-us/windows-server/networking/technologies/pktmon/pktmon

输入 ：我们要监控的玩网卡为 连接到内网网卡的 ip 为 ens224这张网卡系统  
tcpdump -w 生成.pcap文件信息 然后传输到攻击机上下载文件并且用wireshark打开分析他们


打开tcpdump 的手册看到 ：
![[Pasted image 20241201152300.png]]

除了这个之外  在responder-window的github中也可以留下俩这个信息系统，在window版本中的beta版本 这个工具也可以帮助我们去 搜集相关监控信息源  
主要链接：https://github.com/lgandx/Responder-Windows
搜集网路卡中该流量的所有信息 、监听是被动的监听 不会发送任何主动的数据包阐述 
命令 `sudo responder -I ens224 -A`
![[Pasted image 20241201153241.png]]

提示信息点如下 ：
![[Pasted image 20241201154613.png]]
然后 可以查看打开的服务等一些服务设备 以便于后面进行更好的攻击路径的规划跟链条的设计判断 ，
先查看流量数据 确认有流量数据传输 ---》利用responder 查看涉及到的一些服务 ----》fping 的具体存货版本主机的探测功能 
在当中我们可以知道子网是 ：172.16.5.0/24
具体有多少台存活主机 用fping  ：为啥要用fping？ 因为fping 探测功能你的恶化比拼高版本要好 数据列表要正式 
并且能向不同的端口同时多发数据包的ping探测信息装置 且 可以循环风昂视查看  定位细腻系 
具体信息如下 :
`fping -asgq 172.16.5.0/23`
![[Pasted image 20241201161420.png]]

此时我们的效果有  
-a  是仅展示存活的主机 
-s是 打印最终的状态  信息  
-g是 从cidr网络生成网络路标列表 根据指定的ip范围显示 ip列表 
-q 已知输出 进现实存货的主机 
注意 细节如下：
在 咱们的枢纽机 中（172.16.5.225）上执行的结果是：
![[Pasted image 20241201162125.png]]
但是 在 咱们攻击机中 ip（10.10.14.51）上执行如下：
![[Pasted image 20241201162707.png]]
在内网靶机中以内网的身份执行抚平命令可以获得主机数目如下 
三台靶机组成的一个小型的域网络系统 

第二大板块  NMAP 的扫描系统 
![[Pasted image 20241201164307.png]]

![[Pasted image 20241201164436.png]]
![[Pasted image 20241201164506.png]]
采用的是nmap扫描机制 ：
`nmap -A -iL host.txt -oN xxx存储路径信息 `
报告搜集到位：

![[Pasted image 20241201205756.png]]
如何识别用户信息：
当客户无法给我们具体的明文信息的时候，我们需要干一件事，就是 去尝试获取用户信息，前提是现在育种的 建立足够的立足点 目的是获取 NTLM 跟密码哈希 或者明晚呢凭据，在前期阶段收集足够的用户凭据尤为重要，哪怕是最低权限也不要放弃获取信息的时候
### Kerbrute 内部AD用户如何枚举获取信息 
kerbrute有个细节信息  kerberos 预身份验证失败不会触发日志或者警报 
kerbrote 中可快速爆破凭证账户的工具：
https://github.com/ropnop/kerbrute
利用用户爆破的手法进行强制爆破美剧出最终用户账户名以及信息系统 
其中  1.4亿美国常用的用户名如下 ：
https://github.com/insidetrust/statistically-likely-usernames?tab=readme-ov-file
在这里面 常用的是 smith跟 jsmith2 这俩可能得用户名爆破数据库
kerberos 这个 爆破可鞥的用户信息 借助工具 爆破 
其中 我们既可以自己下载预编译好的 也可以自己编译 
以下是自己如何在linux中编译的流程 
linux编译流程：
在 github里面自己看  然后 直接枚举详细信息即可

### LLMNR/NBT-NS中毒 来自linux 
对域的初始枚举 获得了信息 在寻找域控的时候发现了主机确定了细节问题  
网络投毒+密码喷洒 
获取域用户的有效的明文凭据 然后再域中立足，从凭据开始下一阶段的枚举 
评估期间收集凭据 进入立足点的方法：链路本地 llmnr 跟netbios 服务名称 广播尽心高中间人攻击 
中间劫持到密码哈希 收集到一些可能会泄露的明晚呢凭据或者是密码哈希 以用来下一次攻击 

#### LLMNR 和NBT-NS入门 
什么是llmnr 呢 ？
基于域名 dns 包格式协议 允许 ipv4跟ipv6 对主机同一个本地链路，主机执行名称解析     
2022年4月起用的开始 淘汰 llnmr  https://en.wikipedia.org/wiki/Link-Local_Multicast_Name_Resolution跟 netbios 转而改用 mdns（多播的dins）  
NETBIOS这个是  名称服务无连接通信数据包分发服务面向链接的回话服务 等问题 
 NETbios 跟 llmnr 是 在dns失败之后作为识别主机的代替的方法  dns解析失败后的话可以采用这个 来获取著名 
 llmnr是 dns分发的一种 ：原生端口 是 5355  udp端口 ：原理是链路上的一个机器作为其他机器的解释的地址来运行  
 使用顺序如下：  DNS解析失败后用 LLMNR-》NBTNS(udp 137端口号)
 如何想到要使用 中间劫持的呢 ？答案是：当我们使用的是LLMNR/NBT-NS来名称解析的时候 ，多播 广泛发送 ，那么意味着网络上任何主机都可以响应 ，所以 我们可以冒充某台主机 来欺骗广播域中的权威名称解析员，让对方误以为我是一台主机。然后给我发送相关的带有llmnr 跟nbt-ns的数据信息，目的是骗取受害者与系统通信 
当 对方请求主机 需要身份验证或者名称解析的时候 ：提供密码的以便于确认身份的时候，可以借此捕获netntlm哈希 对进行离线暴力攻击，检索明文密码登 

其常见的攻击思路是：采用llmnr/nbns欺骗跟 缺乏smb签名相结合的欺骗手段 一起运行  
缺乏smb签名这个漏洞机制可以采用的是冒充smb凭证攻击的方式行为 

重要核心思想 ：如何触发 这个llmnr呢？
答案是：当我们在解析域名的时候 输错了一个域名地址 ，导致dns解析错误 误认为次主机位置 然后向链路上其他机器广播发送这些地址内容 
因为输错了--》DNS解析失败，标记为未知，广播发送询问谁是这个未知 -->攻击者借助response 说我是！！我是这个未知 你跟我连 ---->借此达到劫持的目的i

如何破解相关的ntlmv1跟ntlmv2密码哈希机制？
LM 跟NT哈希的身份验证协议机制：“尝试用hashcat 跟 john等离线工具破解他们 目标获取明文密码跟凭证 以便达到冒充的目的

采用的工具：
1 responder：专门用于毒害llmnr跟 nbt0ns mdns工具：https://github.com/lgandx/Responder
2 lnveigh 跨平台的mitm平台 欺骗跟毒害攻击：https://github.com/Kevin-Robertson/Inveigh
3 metasploit 有几种 内置扫描器跟 
MITM（man in the middle attack ）中间人攻击  拦截攻击的方式

这一切的目的是为了通过responder 工具等开展中间人攻击的手法 攻击扩展立足点，枚举攻击扩展立足点，主要是为了建立立足点获取足够的信息跟凭证进行仿冒 

常用于以下协议：
1 LLMNR  dns解析多播协议
2 DNS、3 MDNS 多组dns解析 新生代版本 2022年以后用的协议
4NBNS （一种将人类可读的协议转换为ip地址的一个协议类型）5 DHCP 6 ICMP 7 HTTP 8HTTPS 9 SMB 10LDAP  10 WebDAV（web分布式创作跟版本控制 是http的一组扩展协议 代理直接在http服务器上创建内容 ） 11 Proxy Auth （代理授权的请求标志头） 
![[Pasted image 20241203213241.png]]
这个 DCE-RPC：分布式计算环境/远程过程调用分布式计算环境开发远程过程调用系统 的操作行为逻辑 
这个允许程序编写分布式软件的过程 


使用工具responder 
1 responder -h开启工作 
![[Pasted image 20241203214148.png]]
这个工具信息重点关注并且 关注其帮助栏可以大概知道  
-A 选项是去读取查看nbt-ns 等多种协议但是不去毒害拦截任何相应
-I 是处理网卡 监听网卡装置 
-i是指的具体的ip地址的信息 
-6质的是ipv6的信息地址 
-e 是 指的是把所有的ip地址进行毒害拦截
-b指的是基本的身份验证 
-d是 默认在dhcp响应请求中注入 wpad服务器 信息 具体如下：
什么是dhcp中的wpad服务器呢？
wpad 是web代理服务器自动发现代理服务器的意思  借助dhcp的自动发现的代理服务器 
wpad 是 局域网浏览器自动发现的内网中的代理服务器机制 并且 自动设置为该代理连接的企业内网跟互联网那个机制  若系统开启了wpad 的话 就会在局域网自动寻找代理服务器机制，当找到后会自动下载PAC （自己定义访问设呢么地址的时候用什么代理访问的饿机制）
也就是当访问目标特定的网址的时候自动开启的代理服务器机制 表单机制 
目前的话  dhcp服务器对客户端wpad配置 已经失效 而是采用较为简单的dns服务器的方式来进行合理化的配置跟运行 
具体详细链接如下：https://cloud.tencent.com/developer/article/2383691
-P 导致的时强制代理还行身份验证机制 可能会引发登录提示也就是让你强制验证身份的 所以当为探明情况的时候应该谨慎使用他们， 如果在大型企业中  浏览器启动了自动检测设置 也就是hiwpad 的话  -w会自动的捕获他们所有dehttp请求 

此工具将会检测任何请求 ：
其 打印出来的目录存放在 /usr/share/responder/logs内 
hash 保存在关联的日志太重   存放在 /usr/share/responder中 
必须以sudo 身份运行 

第四步：在 枢纽机上以sudo身份启用 responder 获取enss224网卡中内网网段的信息：
![[Pasted image 20241204150546.png]]
使用ens224的原因是 因为ens224处于内网网段中 所以我们要是用他们 
![[Pasted image 20241204150712.png]]
开始捕获哈希等内容信息
hashcat  中 帮助文档中使用
`hashcat -m 5600 forend_ntlmv2 .破解的字典路径`
![[Pasted image 20241204151616.png]]
破解完的信息 你会得到如下 文件：
![[Pasted image 20241204155236.png]]
其中 mssql 跟 smb 这个文件 是 存放了用户名跟破解的hash的关键信息 将其上传到本地文件后
进行本地处理 
如果要处理某个特定用户名的信息 ：、
linux命令如下：
例如 处理 用户名为 backupagent 的信息 只保留他的信息 ：
`grep "backupagent" 含有原始hashcat信息的文件夹` >放到新的文件名中
进行破解：
利用john 破解  默认字典位置1 ：/usr/share/wordlists/rockyou.txt文件命中 
`john -wordlist=字典路径位置 整理后的hash文件`
john往往比hashccat 吃cpu吃的较少，容易运行一些 


上述工具是针对LINUX而言的 hash的破解行为 

#### 下面所说的工具是 window而言的
目标：window工具
场景：LLMNR 跟 NBT-NS中毒获取hash值
工具：lnveigh:https://github.com/Kevin-Robertson/Inveigh
关于此工具的参数说明：
https://github.com/Kevin-Robertson/Inveigh/wiki/Parameters
工具在C：\tools中找到 

先执行：
`import-Module .\Inveigh.ps1`
是指的先执行这个模块内容 并且在独立模块中执行，在独立会话中执行这个内容
![[Pasted image 20241204170327.png]]
第一条命令 :`Import-Moudule .\Inveigh.ps1`
这条命令揭示了局部变量启用模块 ，并且封装到局部模块中  执行 也就是只限定在特定会话中执行  如果要开启全局变量模式的话启用的是 -Global的模式 

第二条命令：`(Get-Command Invoke-Inveigh).Parameters)`
Get-Command ：这个命令查找获取有关指定的命令的详细信息，返回powershell的函数等详细信息
`Invoke-Inveigh`查询命令，是cmdlent的具体引用函数的信息的值
`.Parameters:`属性访问器，提取命令参数信息
在下方可以看到所有的采纳数信息以及具体的数值分析
第三条 在 执行完他们后 只允许 在这个窗口执行对应封装模块信息后，输入：
````powershell-session
 Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y
````
其中  invoke-Inveigh  Y 代表的时同意的含义 -NBNS：是采用了监听NBNS机制  并且进行控制台书输出的同时输出到文件那 

![[Pasted image 20241206110952.png]]

此时可以看到野生飞扬在 上述输出内容中的 hash 
，也可采用方法二：
C# Inveigh 这个源代码可以深入研究探索 变异  
但是自带 的  ，但是现在为了省时间的话，直接用即可 
此代码待深入研究探索：
.\开启exe后 ：进行编译探索 发现这里有句话 `press ESC to enter/exit interactive console`
![[Pasted image 20241206112355.png]]

摁esc进入控制台 并且输入HELP：
![[Pasted image 20241206111306.png]]


点击HELP 可以查看其帮助命令并且查看内部文档 ：
![[Pasted image 20241206111543.png]]
其中 NTLMV2使我们想找的东西  ：所以 GET NTLMV2后 

![[Pasted image 20241206111619.png]]

![[Pasted image 20241206111709.png]]
找到对应目标hash 挪到kali中利用john破解即可 








