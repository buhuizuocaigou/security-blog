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
