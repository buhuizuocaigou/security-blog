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


