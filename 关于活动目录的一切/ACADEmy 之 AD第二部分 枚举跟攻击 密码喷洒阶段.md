概述 ：主要就是 将之前拦截下来的密码进行破解成明晚呢的过程  
用户名跟电子邮件信息可能是在渗透测试的OSINT 的阶段 初枚举阶段收集的，
密码喷洒 是有效的建立立足点方式之一 
以下示例来自于非入侵灰盒评估  使用的是 linux vm跟ip列表视图进行内部访问
可能导致的某些攻击落空 但是看起来有用的：
也就是说极有可能造成误报的攻击方式：
1 https://techcommunity.microsoft.com/blog/filecab/smb-and-null-sessions-why-your-pen-test-is-probably-wrong/1185365  SMB NULL会话 
	插入相关信息：
	1 何为widnwo进程IPC的简述  就是无需身份验证即可直接登录 ，既密码默认为NULL状态 
	smb的NULL回话如同 window进程IPC共享会话一样 
	什么是IPC的共享会话机制呢？：
https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/inter-process-communication-share-null-session
在window中 IPC$称之为是空会话链接，并且window允许佚名用户登录进行 

windows中有个神奇的行为 是 配置适合的权限来陪孩子是佛可以佚名访问共享用户。默认的是禁止使用的，但是不知道效果到底是不是禁用的
看起来 smb的null凭证登录是给了一个空密码登录，但是实际上并不是这样的，他内部存在显示登录跟隐式登录


2 LDAP佚名绑定    采用的某种特定的访客模式 来允许使用者使用他们的过程 ：https://www.ibm.com/docs/zh/cmofm/10.1.0?topic=processes-ondemand-logon-ldap-authentication-anonymous-binding
重点是首先利用kerbrute模式的进行用户枚举
借 jsmith.txt的username 列表 后跟 kerbrute工具枚举有效的域用户进行密码喷洒 后，可以直接拿下攻击路径  在jsmith.txt获取到用户列表 然后在跟抓取的领英结果相结合 生成了密码组合

场景2 
枚举常见用户名列表中 跟领英的失败了后，我观察该公司集团泄露在网上的pdf中的已存在的用户名观察到了规律自己建立了词典 ，在建立攻击用户名词典后，通过这黄总工碰撞方式 来识别域账户中可能具有的密码部分  ：
同时遵循两种复杂攻击链：RBCD 基于资源的约束委派[https://posts.specterops.io/another-word-on-delegation-10bdbe3cd94a]() 跟 影子凭据[https://www.fortalicesolutions.com/posts/shadow-credentials-workstation-takeover-edition]() 最终拿下域控  这俩等学完kerbero 再回来读

kerberos 中的无约束委派功能 ：https://adsecurity.org/?p=1667
神奇的kerberos 跟 ACL列表委派功能 


密码喷洒 的与密码爆破的不同：
密码爆破是：一个个去登录器内碰运气 容易封号
密码喷洒：这个是每个用户之间的 测试更少的部分     但是可能导致账户在域内中的用户保持锁定的功能，并且 可能通过内部网络获得域密码的策略部分，
如何利用密码策略  ：如果一个好的密码策略是 尝试5次就锁定的话，可以谨慎行事，分为两种情况：1 在未打开内网的立足点的时候，也就是目的是进入内网的时候，可以通过别的方式获取密码策略 或者等一段时间在进行喷洒
2  当已经有一个域内账户想建立其他的立足点的时候：可以通过各种方式列举密码策略，并不会担心被发现 

### LINUX中如何枚举密码策略 
工具：CrackMapExec  https://github.com/byt3bl33d3r/CrackMapExec 等工具获取密码策略 
目标 针对目标网络系统进行针对性的密码喷洒实验 ，首要任务 ：避免以及预防无故的密码喷射导致账户锁定 
整场任务的目的：减少次数 并且能碰撞出来合适的密码出来 并且可以减少被锁定的可能性
目前 已知ssh可以链接到的目标信息 
![[Pasted image 20241206165442.png]]
第一步  在攻击机上执行：
`crackmapexec smb `
![[Pasted image 20241206165726.png]]
选择smb 后 进行下一步：
`crackmapexec smb --help`
![[Pasted image 20241206165826.png]]
这是首要任务 。所以放上我们的ip:
后再次查看 注意到这一条：![[Pasted image 20241206165918.png]]
查询得知 在此网站上查询可得知：https://medium.com/r3d-buck3t/crackmapexec-in-action-enumerating-windows-networks-part-1-3a6a7e5644e9
![[Pasted image 20241206165939.png]]
设立目的是为了防止密码锁定  ，这一步的目的是借此探寻出来在内网的 密码策略是啥 ，因为我们已经有了一台枢纽机所以 我们能否尝试在枢纽机进行还是在攻击机？
采用一组正确的域内的账户跟密码 即可收集到密码策略 如下所示
![[Pasted image 20241206170651.png]]
前提是这个机器是连接到内网的枢纽机装置 

第二种方式 ：枚举密码策略：linux的smb 的NULL会话机制：
smb的NULL会话机制 或者ldap的佚名登录机制 可能惠然给我们获取跟域内用户的最低访问权限 
 smb的null策略可以让用户检索信息 不用使用密码  这些配置在默认的旧版本的 windowserver中默认存在但是不会造成很大的事务 
与枚举 的部分 可以采用的额工具有：enum4linux crackmapexec rpcclient 这三种工具 

首先使用的是rpcclinent 
`rpcclient -U "" -N ip地址  `
查询其 文档如下 ：
repcclient 然后使用空密码尝试进行密码喷洒验证阶段，最终结论是验证成功 

### 密码喷洒获取目标用户：
已知靶机练习场景：
1 用户名 ：htb-student  2密码：HTB_@cademy_stdnt!
链接方式 ：ssh                ip地址：10.129.219.87
攻击机ip：10.10.14.23


一 详细用户枚举 ：
第一步收集用户 等各种个人信息 来制作独属于他们的字典库，以及个人的字典库
方法可能得如下：
1 SMB的NULL 回话 也就是无密码会话从域用户完整列表
2 利用LDAP佚名绑定来查询 ldap信息 获取ldap列表 
3使用：https://github.com/insidetrust/statistically-likely-usernames  生成多个密码序列
经典的jssmith类型 列表 10000个 
4 使用：https://github.com/initstring/linkedin2username  linkedlin2 用户名 来生成 osint 直接爬虫通过 领英等数据生成，主要针对国外 ，目前不涉及国内的社交媒体
创建潜在的用户攻击列表
5 ：某个windows系统的或者linux系统的凭证攻击

重点关注可能发生的两个问题：
问题1 ：是如何解决关于最小密码原则 有几位
问题 2：最大可尝试次数是多少，试错多少次会锁定？

上述两个问题聚焦在时常产生的密码策略内部。，观察是否客户可以给出，若不给出我们该怎么处理

第一种获取方式：靠smb 的NULL获取用户名字典信息：

关闭了虚拟机的vmci通道后 保证了虚拟机域虚拟机之间某些通信首先
解决办法：将docker 装到ubuntu内部

第二步 smb null 拉取用户名列表收集凭证
使用场景： 已经进入内网计算机 或者已经可以访问内网计算机但是无后续凭证。
采用方法：LDAP佚名绑定 +smbnull 回话尝试搜集 “
目的：获取有用的凭证信息做进一步渗透，准确列表跟密码策略 做密码爆破 获取system最高权限或者往下一步方向去渗透

尽量获取到 system账户凭证问题，用 smb null或者ldap佚名访问也可
工具使用 :
1 enum4linux:https://github.com/CiscoCXSecurity/enum4linux
2 rpcclient:https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html
3 CrackMapExec:https://github.com/byt3bl33d3r/CrackMapExec
举例分析：
场景一：在枢纽机上执行 对内网段的扫描行为：
命令：`enum4linux -U ip address' 
执行结果如下:

![[Pasted image 20241219094241.png]]![[Pasted image 20241219094530.png]]
做文本处理
上述做文本处理：
`|grep "user:"`：筛选出user的行 
`cut -d"[" -f2 `:-d 后面指的是从`[`前不要了 -d（deleted）保留从这个符号往后的所有内容，然后 -f1 从之前那个符号开始往后第一个 字符 开始保留 
就变成了这个样子
因为-d' 从1 开始往右排序 `[:1号位  xxx：二号位`
![[Pasted image 20241219095823.png]]
在把右边括号删掉：
`cut -d "]" -f1`![[Pasted image 20241219095923.png]]
重定向后就是用户列表 ，
enumdomusers 这个是列举的意思 ：

使用rpcclient 对 其用户进行空密码登录采用smb 模式 
具体命令如下：
`rpcclient -U "" -N ip address`
来源：
![[Pasted image 20241219101511.png]]
这个-U  是列出username  允许 空用户名的存在
-N 是 允许空密码的存在 
目的是列举域内的用户名 进入后:
![[Pasted image 20241219101756.png]]
在此模式下  我们再其官方的man文档中看到：
![[Pasted image 20241219101926.png]]
输入这条即可得到 美剧 users的目的 输入后我们可以看到：
![[Pasted image 20241219102145.png]]
信息获取成功

`crackmapexec 的smb 模式 获取用户信息`
效果如下：
`crackmapexec smb xxxip address --users `
其得到的效果与上述的表达无任何差异

### LDAP的佚名攻击来收集用户信息：
能采用的工具或者单词列表：
1 widnapsearch：https://github.com/ropnop/windapsearch
2 ldapsearch：
https://linux.die.net/man/1/ldapsearch
 此处为简介 具体详情可以关注 ldap模块 的详细内容 
 ![[Pasted image 20241220105400.png]]
 这个模块是 需要选中具体的所有全部id 的部分，指定授权ID 来进行查询，而授权ID是授权店 的一部分
 指定类似于 ：
 ![[Pasted image 20241220105548.png]]
 指明 DC的具体内容  
 而-b指的是：`-b `: 指的是：
 ![[Pasted image 20241220105705.png]]
 这里，-b 是指代 去进行搜索   
![[Pasted image 20241220111127.png]]
关于其属性等详情 请移步ldap学习：

#### 使用kerberous 枚举用户：
什么是kerberous: kerberos 的预身份验证 
一种新的验证手法 且用此工具不会生成，4625的事件报错 也就是说 不会出发任何的事件日志错误警告 ：https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625
采用一种特殊的枚举手段，在某种庆康喜爱  无预身份验证的前提下 像 dc也就是域控制器中发送TGT(票证分发中心)，执行用户名枚举等功能，如果 KDC （密钥分发中心相应失败后）也就是PRINCIPAL UNKNOWN后 则用户名宣布无效，当宣布有效的时候皆为用户名存在 
利用kdc提示 kerbero预身份验证机制进行用户名的枚举功能 

单词表：
https://github.com/insidetrust/statistically-likely-usernames
命令如下
```shell-session
 kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt 
```
其在帮助文档内如下展示
：
![[Pasted image 20241221101623.png]]
userenum  后 选择 -d 指定 域名 --dc指定dnc  最后加上自己得枚举单词列表即可

站在防御者的视角来看的话 ，如果想防御并且察觉到此攻击的内容， 检查siem中事件日志中标有id为：# 4768 https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768
即 若发现 事件id名为 4768 的日志 即为 攻击者可能采用了这种攻击方式来枚举用户名信息内容
需要查看 日志4768信息并且调整TGT的攻击策略跟思路
https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-kerberos-event-logging
启用特定的日志来记录并且 检测他们 


第三步  当我们前面成功获取到 用户名跟信息来源后下一步的内容是使用密码碰撞 来尝试获取最终凭证信息 分为 linux跟window部分 内容 
linux篇章：
深入远离分析 https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/

工具是 rpcclient  ：推荐原因：因为是 不会立即显示有效登录 不响应代表攻击没成功，一旦响应后则表示攻击已经成功了 
对于密码喷洒  
场景如下：假设一台域内的机器的用户名跟密码 并对其做密码尝试 ：
测试密码  Welcome1 这个密码 是适配那个用户 
采用 工具rpcclient  语法 是 bash 
`for u in $(cat valid_users.txt);`:将 之前已经选出来的usersname.txt的文档依次列举出来并且赋给 变量u 上面，这样 u上面就具有了很多username 
`do rpcclient -U " $u%Welcome1" -c "getusername;quit" xxxip地址  `
这句话中的-U  具体help命令文档如下：
![[Pasted image 20241221104151.png]]
将其 -U 放到后面  达标了 是 列举出 username  且 $u 是我们之前的用户名 变量的名称  %password 代表了百分号后是 passwrod的内容 去尝试 Welcome 1 密码列表 尝试同一个 密码的序列 
-c ：
![[Pasted image 20241221104346.png]]
指的是调用command控制台命令去 调用控制台并且执行 ：
getusername 这个命令细节 获取用户名 在退出  后加入ip地址  指定ip地址的内容 ，这个是针对每一个在列表中的额用户名   将其 输出  做一个
`|grep Authority;` 做一个筛选 后 done 结束循环  即可得到想哎哟的额内容给你 
![[Pasted image 20241221104807.png]]
-c是触发这个命令 也就是commands 的内容 逻辑。即为 在控制台内的内容  rpc客户端成功链接上了以后的内容分析 其中 我们需要重点处理的是关于：
![[Pasted image 20241221104928.png]]
是getusername的方法逻辑

方法二 ：
使用kerbrute 进行攻击：
具体命令 ：
`kerbrute passwordspray -d inlanfreight.local --dc ip address username password`
这是 为什么选passwordspray的内容 ：
![[Pasted image 20241221105117.png]]
在选择后 再次在命令台查询帮助可知：
![[Pasted image 20241221105424.png]]
需要flag 若干，以及 username 的wordlist 以及最终的猜测的具体密码

方法二 ：
对于flag我们选择 -d 指定控制器的名称 --dc 指定具体的kdc 以及dns的地址  也就是他们的ip地址或者dns地址 
制定完后 放上username 的 表单  对密码输入后 得到的最终结果如下：
![[Pasted image 20241221105753.png]]
注意 此攻击是在枢纽机上展开的 
方法三 ：
使用crrackmapexec 利用smb 机制进行 密码碰撞 产生数据以及凭据信息内容：
当我们提到密码喷射的时候可能想到的一种思维方法是，是否可能造成密码复用现象 即为 密码复用，就是指的同一个密码在不同场景进行重复使用的过程。
本地账户中的进行内部账号的密码枚举以及尝试任务工作

#### 针对于windows部分密码喷射攻击 ：
密码碰撞枚举功能 ：

工具：DomainPasswordSpray  ：https://github.com/dafthack/DomainPasswordSpray
借助他来搜集用户，可以在未提供域身份验证的时候执行他们 来尝试获取域中更多权限的凭据信息 
![[Pasted image 20250108172430.png]]
其poc：
`invoke-DomainPasswordSpray -Password xxxx -Outfile -erroraction`
来源：
![[Pasted image 20250108195503.png]]目标 ：爆破出来Miami 并且将其输出出去  -outfile解释多久是这个 


如何防御：
减轻防范 ：
1 多因素身份验证  OTP  短信确认 ，多因素认证 等级制泄露用户名等  
2 与用户账户登录 最小权限原则设置
3 保持特权用户账户的单独性，并且详细区分权限原则的问题
4 南猜测的密码 密码本身的变体 

日志中可能出现的事件攻击 以及可能的影响 ;
可能会出现一场日志 报警  ：由于可能是因为 无限登录尝试导致的 ，所以可能会产生跟这个相关的事件报错信息：https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625

（2） 身份验证失败信息 反应了 可能的ldap密码喷射尝试信息 ：
启用kerberos可以检测他们https://www.hub.trimarcsecurity.com/post/trimarc-research-detecting-password-spraying-with-security-event-auditing
还有后面的：https://www.hub.trimarcsecurity.com/post/trimarc-research-detecting-password-spraying-with-security-event-auditing
密码喷洒的原因是自动猜测密码 

可能会触发特定的事件 比如  ID4771：kerberos
![[Pasted image 20250108202744.png]]
注意4625事件，的id



### 深入兔子洞 
#### 板块一：如何绕过策略：
这个板块一 的目的是 为了通过枚举一些针对于活动目录的安全策略来达到，了解可能针对活动目录开启的安全机制，并给出对应可能的绕过策略  

讨论 当拿到账号跟密码后我们该做什么。。。
这里规避掉了AV绕过 也就是说 window 的防火墙的绕过等功能的学习，如果想学习这些的话 单独找资源去学习，这里先假设无防火墙 （因为这里重点是整个AD的概念建设以及架构类型框架的搭建 
思路：
当进入基础的账号后 ，我们首先要做的是 对当下所在环境信息做枚举，信息获取，尝试
该做什么信息呢？ 尽量用该主机原生应用去使用，方式泄露等问题，

一切的核心是防火墙的绕过等功能，关键信息点在于 如何了解到此时所在防火墙的配置信息。
首要的第一步是 获取Window Derference信息 

可能枚举：

一 安全策略信息 （关于 Window Defrenence )
如何查看widow配置信息呢？
Powershell内置的Get-MpComputerStatus 获取当前的defender装阿嚏 ：
参数 ：RealTime ProtectionEnabled 打开：
![[Pasted image 20250109163558.png]]
在命令行输入：
`Get-MpComputerStatus`后发现弹出如下文档：其中  这个RealTimeProtectionEnable 重点揭示了 真实世界的防御攻击等方面的准备 如果是true 证明该计算机已经打开了window deference 做好防范 


Applocker ：应用白名单 ：
微软的官方链接：https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/what-is-applocker
了解的目的：通过此了解到哪些应用不受管控也就是哪些应用允许进入系统不会间似乎 ，

一般防范于 powershell等 cmd程序 但是均可绕过，且 组织 powerhsell 可实质性文件 ：
也就是不让 该用户执行 传统的powershell文件 但是往往会忘记其他的自带的位置 比如 ：
https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations.php
![[Pasted image 20250109164248.png]]
如果被禁了powershell。exe的位置 可以从这些默认自带的路径中尝试找到并且引用
然后进行尝试绕过 ，这些技术上都可以绕过 offsec的 osep绕过技术中讲解

在Applocker中我们可以看到到底哪些应用可以通过白名单的方式进入系统内而无法被察觉到，在posershell中的话 ，使用 `Get-AppLockerPolicy`模块可以进一步获取系统的相关有效的Applocker的策略信息：
主要是获取GPO组策略的信息内容 
微软相关链接：
https://learn.microsoft.com/en-us/powershell/module/applocker/get-applockerpolicy?view=windowsserver2025-ps
![[Pasted image 20250109165435.png]]

#### 可能性三 ：关注点三 ：powershell 的约束性语言模式： “
防御者可能会设置powershell约束性语言：即规定【powershell在远程调用的时候可以用什么内容同时也规定了不可以用什么内容的模式， 然后以此来尝试防范攻击者进行powershell调用等攻击模式
什么是约束性语言呢？
https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/
具体总结为下：
规则：当采用的是device Guard 或者是 Applocker 的模式的时候即应用白名单的时候， 为了防止配套的攻击， 故令其powershell 模式必须在受限制的模式下面进行下去，支持对某种敏感语言跟语法规则的限制
但是有绕过的可能性 ：
例如 帖子中所述的内容类型，文件绕过或者说是 直接开启另一个powershell的方式进行绕过，
这不是今天的重点  重点是掌握约束性语言的内容

命令在这里：
![[Pasted image 20250114215055.png]]
在宿主机尝试如下：
提示fulllanguage 是 表示没开启语法约束
而提示 constrainedLanguage 的话是开启了语法约束 powershell版本

防御者可能采取的措施四LAPS:
大概措施是，管理员设置的密码管理策略，其基于windows进行的
重点是查找哪个组有权限进行这些内容 
github对应的工具  ：https://github.com/leoloobeek/LAPSToolkit
![[Pasted image 20250115094027.png]]
这相当于他们俩之间权限是分开的  也就是说 domain 管理员用户跟laps admins  尽管是管理的一个域 但是他们很可能是两个账户 分别管理不同的职责 
权限范围大的可以包含于权限范围小的内容
但是小的干不了权限范围大的事情 

第二个命令  ：
`find-AdmPwdExtendedRights`:用于在启用的LAPS的计算机上 读取任何具有去哪先的组 跟具有所有扩展权限的组的权限 





第三个命令 ：
`Get-LAPSComputers`针对过期的laps的计算机而言，去搜集相对国球的密码信息  ，
为什么要试试这个命令 ：因为 https://learn.microsoft.com/en-us/powershell/module/laps/get-lapsadpassword?view=windowsserver2025-ps
![[Pasted image 20250115095312.png]]
利用了这里的可能以明文形式存放密码的机制来进行查看，观察是否在整个体系内可能发生密码泄露等可能得问题 


这些上述实操阶段打算在后续待得到证实
