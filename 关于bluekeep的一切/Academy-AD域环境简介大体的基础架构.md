初始AD域 
一 历史路径：
WINDOW 2008server 引入 ADFS ：
同时引入sso功能  sso的引入保证了 同一个lan的用户只需陶登陆一次就可以 ，只要他们在同一个lan无需重复登录

ADFS 细节：
两个安全域之间建立信任然后进行身份联合 ，
A跟B之间互相通信，然后 A中的用户对AD的服务标准对用户进行身份验证 ，同时发出一个令牌，并且包含一系列有关声明，包括身份等，B端验证这个令牌，并且为本地服务器发出另一个令牌接受声明身份，然后杨的话 A端B端无需访问验证对方的数据库密码登信息，只需要借助一个第三方机构所颁发的令牌去无条件信任对方，然后让对方可以控制自己账户
类似数字签名的机制 

总结：借助第三方机制来进行中间商认证机制，颁发权威的令牌来表示已经成功认证 
主要是将其内容打包成第三方令牌形式 


server 2016引入了 gmsa功能 ：
什么是 gmsa？
更高效的身份解决方案以及模式 英文的全称为:Group Manager Service Account简称为gmsa
正式初步了解AD  
Acitve Directory 结构 
主要是提供的是身份那个曾跟授权工鞥，集中管理资源，并且使其可供同一网络上标准用户跟管理员使用，ADDS存储用户名密码信息 
	AD缺陷可以让我们用于获取立足点 以及横向纵向移动访问一些资源
	本质上AD是个大型数据库，且域内的所有用户都可以访问的数据库，没有附加权限的AD用户其实可以访问大部分内容 ：
	1 域计算机 2 域用户3域组信息4默认的域攻略 5 密码策略 6域信任 组织单位  功能域级别 gpo等 acl等

AD的大概结构：分层树 多茶树 
顶部包含多个域 林是安全便捷 搜友对象是管理控制下 
一种嵌套类型的结构类型 
域与域之间建立关系远比要在本域中创建关系要快得多，更容易，如果管理不当的话 会发生各种违规的问题 
大概结构如下 如同一个多叉树一样
![[Pasted image 20241023193257.png]]
![[Pasted image 20241023193344.png]]
在域中的规则如图所示：
在A域跟B域中，其中 A中的顶级域下面的子树是无条件信任上面的域的，且B中的子域也无条件信任上面的域，并且A中的顶域可以跟B中的顶域进行沟通信息交换，但是 A跟B的子域在没有添加条件的时候是无法进行沟通的 必须设置信任才可以 
AD的术语 ：
1 Object ：这个是可以将对象定义为AD域中的任意资源 ，
2 Attributes（属性）：AD的域的话都有一个关联的属性的值，并且包含hostname DNSname 
AD的话 这些东西在AD域中的话都有一个既定的名称，不管是
比如常用的功能 ：
、(1)sAMAccountName：老版本的window登录名
    (2)userPrincipalName(UPN)电子邮件格式的用户登录名
       （3）cn（Common name ）对象子啊目录中名称 
          (4)mail 电邮地址
             （5）objectClass ：定义对象的类型 
             或者是 hsotnmae fullname等等 


3schema：ad的架构类型并且跟acl访问控制列表息息相关
在每个对象中 会归结到一个类中 ，这个类跟java类 c#中类的定义差不多，主要是 某种对象属于是什么类别的信息模型，每个对象都自带各种属性，从类创建对象的时候叫做实例化，
比如对象computer 在ad中的类为 COMPUTER类
 如同java中的 中的对象跟类的区别跟联系一样 
 4 Domian ：这个代表的是 每个domian是一个类型，群体的集合体 ，且这每个域的信息类比与一个国家之间省与省之间的联系等内容 
 5 Forest：一个森林包含下面好多的域内容 信息 ,且forest森林是他们的域的顶层容器的内容 
 每个forest 可以独自运作的同时也可以 协作运作 
 6 Tree：根域指的是 一个单独的根以及下面的集合 
 森林跟树的结合 就类似与408中的数据结构的树跟森林的集合体
 从一个root  node 到叶子结点的单独一条路，其指的是一棵树 且在同一个域下的树与树之间可以独立也可以建立信任关系
 且同一个森林下的两棵树没有共享名称 ，
 插入：名称解析 ：`corp.inlanefreight.local`而言其 表示方式是从forest的底层到顶层 描述的既
 corp是子域 （subdomain） 是树的最底层 也就是多叉树叶子结点的部分 ，
 `inlanefreight`这个是次级域 主要是代表的是组织公司项目名称
 `local `是个顶级域名相当于最上层
 对于 `Domain`而言 这个是一个域名 且它包含对象等各种属性以及安全边界管理策略等问题 
`tree 跟forest:`森林是ad的最顶层，且包含多个树，相当于多叉树的最顶层 

 `Container`不包含其他对像肚子房子啊末位 
 GUID ：Global Unique Identifier 这个标识符：
 分配的唯一一对128位的值，并且guid值在企业是唯一的 类似与mac地址，每个分配对象都有一个GUID ，
 同时还能再属性中查到，相当于是身份证 跟SID有异曲同工之处
 查询命令是 ：objectGUID 
 可以枚举并且查看属于该域的所有信息

四：security principals 安全主体
操作系统中的任何内容 包括各种机制，以及各种资源可以访问的域的对象内容，并且他是由AD管理的并且跟安全账户管理器 SAM管理的有关 密码不是AD管理 是在存放在SAM当中去管理的 

什么是SAM 安全账户管理器
安全账户管理器：SAM指的是 :
主要是对远程用户的身份验证，并且使用加密措施方式未经身份验证的用户对系统进行范文，；
SAM是一个数据库系统 并且 他们的防范措施是   NT4.0的 SYSKEY功能
syskey 进行加密的过程 
  存放用户密码的一个数据库 并且以哈希的模式存放子安其中  且需要 SYSTEM权限才能查看
  路径在 ：
  `%SystemRoot%/system32/config/SAM`此路径
  存在于 NTLM哈希中 ：存放密码的一种方式手法 ：
五：专有名称：（DN） Distinguished Name
这个描述AD中的对象的完整路径信息，这个是专有名称 的信息 是属于某个人的专属邢敏改的额迷城  
并且描述AD中的单个组件 且为独一无二的组件信息内容 
六：相对专有名称（RDN）
可分辨名称单个组件，只需要保证在当前这个级别同一级别中可以区分他们即可 
保证大类不同 但是不同大类下面 的小类别名称相同即可
CN：通用名称 OU 组织单位  DC与组件 

![[Pasted image 20241024175405.png]]
### Active Directory ，user 中的userprincipalName 属性
powershell ， Get-ADUser ，  属性的值：
(1)
这个属性在本地的AD中不是必须的，用户无需分配值。
(2)AD跟mmc 强制执行的唯一值，
(3)为了将账户与office 365同步，采用的是电子邮件的地址
(4)https://learn.microsoft.com/en-us/archive/technet-wiki/52250.active-directory-user-principal-name

FSMO 角色：
DC 安排成一个 玲玲获得单主操作的角色，DC（域控制器）能够对用户进行授权跟身份验证 不会中断，
因为早起的DC是一个带头大哥 其他的是小弟的模式，一旦带头大哥出现问题，则必须等到恢复带头大哥的控制权后 ，，主DC才会发生故障

五个FSMO角色：
Schma Master     Domian naming master      一个林子 各一个  
Relative  ID  rid master 跟  Primary domain Controller Emulateor  每个域一个 ，跟 Infrastructure  Master 
 当新加入的 域 的时候 只会迁移部分东西  比如 RID  PDC模拟器 等基础结构分配给新的域 
具体角色后续细嗦
全局目录
GC存储当前域中的对象的完整副本以及林中其他域对象的完整的副本，标准域控保存 其域，林中域对象的完整副本，GC在域控下的工鞥 执行下面功能 ：1身份验证 2 对象搜搜  

RODC 只读域控制器  有用制度的数据库 等信息：
只读的AD 数据库，不会缓存任何的AD账户密码（除了本账户密码除外 ）：不会有AD数据库，等SYSVOL 或者DNS做任何更改，并且包含一个只读的DNS服务器，并且 可以减少环境中的复制的流量的量 即可
总结：只能读不可以改，的一种AD域环境 
防晒值复试 对其产生的一种保护且里面不存放任何信息 ，或者说信息无法从DODC上打开突破口 

复制：repliacation  发生条件 当 AD对象更新从域控1 传输到域控2 的时候 AD中会发生复制，添加DC 创建链接，KCC 服务器建立，复制可以确保DC同步类型的处理  
AD DS中的服务器对象表示方式，站点中的域控服务器， 在进性复制的时候 必须两个域控之间建立链接后进行 。

SPN 服务主体名称：
唯一标识服务实例，kerberos 使用它们将服务实例跟账户练习，允许客户端进行身份验证机制 
SPN 将服务器的实例跟 登录账户进行关联，计算机中安装的多个实例，可以有多个spn ，
是相当于 SPN的存在是类似与用户身份证号的一种存在形式，给定SPN 在一个账户注册，并且将其编写进AD中的对象舒心，当链接的时候 会生成服务对应的 身份id号，只为了服务服务的东西

这个 spn存在可以借此来进行身份验证 从而不用知道账户名称

GPO（Group policy object ）
是策略设置虚拟集合，每个GPO有一个 唯一的GUID ，并且GPO包含于本地文件系统设置跟AD设置 ，
ACL这个访问控制表  这个表中是适用于某个对线改的ACE的集合。
ACE初级访问控制条目，ACL中的每个 ACE 都标识委托人以及，真丢受托人的允许拒绝访问权限的问题
，
DACL ：自主访问控制表，这个定义哪些安全原则，
这里面定义了安全原则 被授予被拒绝对象的访问：包含ACE列表，并且系统检查对象的DACL的ACE是否符合 如果压根没DACL 则全部敞开大门 ，如果有DACL的话，且无ACE的内容的话，直接拒绝访问尝试 并且挨个搜索检查DACL中的ace直到检查到位为止

SACL ：系统访问控制列表：
允许管理员记录对受保护对象的访问，ACE指定导致安全事件日志，生成记录访问类型尝试。

FQDN ：完全限定域名：
主机名.域名.tld
定位相关对象在 树中所处的位置在哪里，FQDN 可用于在不知道IP的情况下直接定位 
直接锁定目标主机的地址  FQDN 相当于 google.com 可以不用IP即可知道锁定位置 

Tombstone
是AD中的一个容器对象，“回收站”  定期回收   
跟他关联的 属性值是 `Tombstone Lifetime  属性isDeleted 设置为TRUE`
超过生存时间后 直接完全删除  ，相当于是“回收站”的固定删除时间
默认是 60/180天  
还有一种情况是  域中无AD回收站，他就成为了 Tombstone 对象，并且 大部分属性剥离 ，并且放置在Deleted Object 中 持续的时间为 tombstoneLifetime 这个时间但是 恢复 不全 

Active directory   
AD回收站的最大属性是 已经删除的对象的大部分属性会保留 ，这样有助于完全回到删除前的状态 
https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/the-ad-recycle-bin-understanding-implementing-best-practices-and/ba-p/396944

AD 跟Tombstone是属于删除的操作的双保险机制 
![[Pasted image 20241026151051.png]]
注意时间范围 的设置 具体的函数名 ：`msDS-deletedObjectLifetime`
这个与生存期相同，负责管理已删除对象生存期跟Tombstone生存期的
![[Pasted image 20241026151225.png]]
https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/the-ad-recycle-bin-understanding-implementing-best-practices-and/ba-p/396944
SYSVOL：
系统卷：文件夹跟 共享存储域中公共文件的副本，系统策略，组策略等 执行 在 AD环境中执行各类的脚本 ：https://networkencyclopedia.com/sysvol-share/#Components-and-Structure
这个机制是 SYSVOL共享属于基石 既为 window域环境中不可或缺的一部分 ，存放的 GPO跟脚本呢的中央存储库 
	 定义 sysvol共享 ：这个是 每个域控共享的那个目录 负责复制文件的关键组件 。相当于是公共部分文件的副本机制，以及所有的需要在域中进行共享的文件
	 
	 
这个 SYSVOL里面有啥呢 ？
1 GPO（专属于 SYSVOL）这个是ad的核心功能 并存储在 SYSVOL中，管理跟集中配置AD中的操作系统 app跟用户设置 等行为 ，数据存储在 SYSVOL共享中去
2 脚本 跟SYSVOL：包含登录跟注销脚本 
3 复制跟一致性 保证每个机器中的asysvol 都保持同步功能 

SYSVOL的组件跟结构 :
1 SYSVOL ：包含在sysvol所有其他组件的根文件夹 
2 Policies (策略)：存储AD域中应用告诉哦欧阳组 的策略  且包含的唯一文件夹 唯一很重要 
3 Scripts Folder：脚本 记录了管理的信息记录
4 GGPTS  group policy templates ：每个GPO的文件夹中 并且管理模版文件的形式 包含域计算机以用户的策略设置 

sysvol的复制过程:
之间的转移 机制 ：复制机制，每当对一个域控制器的 SYSVOL 的内容进行更改的时候，并且更改复制到域中的其他域控的sysvol中 且同步信息 即使同步 能否传递 脚本呢？
他是用的实际上是同一组数据

复制的协议 ：FRS 到DFSR ：
FRS：文件复制服务 且 效率低 
现在升级了 DFSR  这个 引入耳聋 复制机制 高校  检测跟复制中更改的部分 且用了差异压缩的原理机制 
SYSVOL 的管理跟故障排除
可能会 执行 备份 跟恢复 还有就是报警监控工鞥 

AdimnSDHolder ：
管理AD中标记的部分 特权的内置单独ACL ，ADprop 专门检查 下面的保护组成员是否用了正确的ACL的功能 默认的时一小时检查一次 ，   执行acl篡改攻击的时候，一个小时 挥别删除 或者说管理员设置了新的时间，得选择性进行绕过功能 ，并且如果被 SDprop攻击的时候，权限被删除 持久性丢失 

dsHeuristics：
目录服务对象设置的字符串值，定义多个范围配置相当于是 受保护列表 不受 上述 AdminSDHOLDER 这个属性的影响，他讲不会被删除 
前提是 通过 `dsHeuristics`删除的某个组 

adminCount 属性决定了SDProp是否保护用户（决定了是否会被定期删除ACL 清空脚本），他有如下逻辑：0 用户不受保护  如果是value 的话 是 收到保护
如果是1 的话  攻击者通常会寻找并且设置 adminCount 的值 并且设置账户为1 作为目标的值，通常为特权账户 可能会加大入侵 可能性 

站在攻击者角度发掘可能存在的攻击面：
1 权限继承的控制 ：当某账户的 adminCount=1 的话系统自动认为是管留言账户 自动启动adminSDHolder保护也就是说他所制造的acl表不会被删除而是会被保护器阿里 
2 AdminSDHolder 机制：这个标志定期检查 `adminCount=1`的对象 并且 将权限设置为 AdminSDHolder形同  ，在执行  这个就爱你差的时候会自动修改 



ADuc  是个GUI控制台 且管理AD的用户 组跟各种功能 

ADsi EDIT 指的是管理AD中的GUI工具 且提供访问权限强大之处远超过了ADUC  设置删除对象的任何属性，允许用户深入的访问AD 等 

SID历史  ：保存对象之前分配的任何SID  迁移的时候 保证了相同的访问级别  如果设置为不安全的话 ，如果未启动SID删选 （或者是 提升访问权限的）
他可以带来什么风险呢 ：可以直接用另一个林中的 管理员的SDI 注入到里面 然后这样子迁移到另外一台机器的时候就可能会获得 SID的权限  如果未开启 SID 的过滤 也称为隔离的话，可以注入 且身份验证的时候可以添加到用户令牌中来

NTDS目录：
NTDS.DIT文件 AD的核心 文件 存放在 `C:\Windows\NTDS\` 数据库 用于存放所有的AD核心数据 
一旦达到完全的域入侵后，即为拿到SYSTEM的权限后，就可检索此文件并且提取hash的系统，并执行传递哈希攻击 等破解存储的密码资源的问题 
如果 系统启用了 

![[Pasted image 20241026161146.png]]
则NTDS.DIT 存储在设置此后的创建或者更改密码所有用户的明文密码，一般在明文验证 的地方 而不是用 kerberos 验证

MSBROWSE存在于早起的网络协议当中   11 nltest  查询widow的主浏览器获取域控名称 

#### ACtive Directory 对象：
对象：object ：指的是 ： domain computer ou groups user printers 
其细分为如下几类：
1 Users：（leaf objects）
相当于二叉树中的叶子结点的值，另一个是 miscrosoft exchange 中的邮箱机制     USERS拥有 SID  跟 GUID   里面包含了很多信息 ，且即使是最低资源的 里面有很多信息可以利用手机美剧
2 Contacts：是leaf objects 的安全主体仅仅包含于 GUID 的图像 ：
3打印机 是 leaf object 仅有 GUID无SID灯 
4 计算机 ：是leaf objects 他们被视为安全主体  是 具有SID 跟规定的部分 ，
5共享文件夹：
可以供所有用户访问，没ad账户也可以访问 ，不是安全主体 石中玉GUID  无SID
6 group  是视为 container object ：安全主题  他包含其他的对象  具有SID 跟GUID
7  GROUPS 应用bloundhunter 去发现嵌套组 的模式 组与组之间集成的模式 来发现合适的 权限分配问题
嵌套组常常是攻击模式的一部分  
8 OU组织单位 ：
系统管理员可以用于存储类似对象的便于管理的容器 ，OU 通常是管理任务委派，无需授予账户完全管理权限
高层可以 管理任意分配儿子的ou的权限的值 ，并且  如果是某员工顶级的OU 的话，需要注意的时 其旗下的所用户u都尅有具有此 ou应的权限的值 
OU可以干的任务有：
1 管理域内用户跟组自己的组策略 2 创建或者删除用户 3 修改组成员身份 
领域 ：
域是AD 结构 组内的 OU 跟每个域有自己的独立的数据库跟策略集合 兵器呃可以应用到组内的所有对象上 ，
2 Domian contorllers 
这个是大脑 机制，核心的架构机制 
3sites ：这个站点的含义是跨一个或者多个子网的 一组使用高速链路的计算机 ，跨域控制器的高效运行
4built-in 安全组的机制 :
内置的默认安全组 
5 FSP 是在AD中创建的对象 表示受信任的外部的安全逐日 ，当外部中的用户实体的信息添加到咱们是之后 会自动创建者个FSP  -=其中包含来源 的SID  FSP在特定的`ForeignSecurityPrincipals`的特定容器中创建 信息 ：
相当于是一个身份排 表示你从哪里来的 为啥来的

Active Directory 功能
五种 FSMO 角色：
角色与分配：
Schema Master  管理AD 模式的读/写 副本 定义了可应用于AD的所有属性 

Domain Naming Master 管理域名 确保不会在同一个地方创建两个同名的域名

RID（Relative） mastrer   ID  分配给域内的DC 并且用于西对象 ，确保 SID的内容不相同  
保证了唯一性

PDC Emulator  ：这个是域中最核心的DC 并且相应的是身份验证请求逻辑内容，并密码更改 跟管理的组策略性 GPO PDC模拟器 维护域内时间

INfrastrusture  Master  这个是预制件转换guid  sid 跟dn 单个林中 进行通信  其中ACL中显示明恒 
https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc754918(v=ws.10)?redirectedfrom=MSDN

https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/active-directory-functional-levels
这两类信息界别  功能几倍 揭示了不同版本之间的 域跟林的信息工鞥 

trust  ：
建立在 forest-forest 跟 domain-domain之间的身份验证 允许用户访问用户所在的域，
信任两个域之间创立链接
parent-child  统一个林的域 子域、父域 的双向可传递的信任
Cross -link 子域之间信任加快身份验证 
External 两个独立域之间会传递低信任  
Tree-root ： 林根域跟新树根与之间双向传递信任 
Froest 
具体图如下：
![[Pasted image 20241026174740.png]]
在上述途中存在信任 transitive 这种情况发生 
1 可传递信任意味着新人扩展到子域信任对象中（可以继承的信任机制）
2 非传递信任中，只有子域本身受信任（之有自己本域中的受信任）
信任设置为单向 ：双向均可  
单双向造成的变化：1 双向：两个信任的域都可以访问资源两个数据互通
                  2单向信任
针对箭头指向而言 ：  箭头的接受方 指的是信任方（trusted domain)
        箭头的出发方指的是 受信任的方
        A---> B 指的是 B 收到A的信任  可以进行信息交换等功能方式 。


#### Kerberos DNS  LDAP  MSRPC 等四种机制  操作协议机制
1 KERBEROS :
相互验证身份来对其进行身份验证，或者用户跟服务器验证他们身份的过程，基于票证的无状态身份验证 ，依照票据的身份  去传递信息 而不是通过传统密码的性是，
ADDS 中会有一个 颁发票证的 kerberos 分发中心KDC 当发起都跟路请求的时候，他们验证身份的客户端会从KDC请求票证，   
有个第三方机构 kdc  用户传输密码 跟信息 是跟kdc 确认 当kdc确认没问题后，给他颁发一个“通行证”这个通行证  TGT  票证授权票证，然后 TGT 交给域控气质 授予相关的服务，然后 在将其TGS提交给app等 

这样子的话 可以将密码跟用户名跟区分开来 并且保证 密码不会通过网络传输
 而且KDC 无法存储 之前的交易 不存在历史记录追溯的功能
身份验证的过程：
1 当用户登录后 先将其密码转换为 NTLM哈希 加密TGT  然后
2 DC上的KDC服务检查认证请求 ，并且验证用户信息是否正确 ，big你企鹅创建TGT  给用户
3 用户给DC出示 TGT请求特定服务 TGS票证  如果TGT成功，则 复制其数据 创建TGS 
4 接着用 NTLM哈希传递  并且 TGS_REP 造成用户传递
注意  这时候开放的端口是88 TCP 跟UDP  
当 找茬开饭改的端口88 可以找到 能跟 Kerbros 的服务协议 从而找到域控

2 DNS ：
DNS是将主机名解析为IP地址 并且应用于内部网络跟狐狸啊我那个  
AD DNS 促进服务器，，动态的DNS时系统IP发生变化的时候自动更改 DNS数据库， SRV是AD在维护网络的一种方式 

![[Pasted image 20241029093722.png]]
可以通过 nslookup +主机 /IP地址这种形式来保证dns地址跟主机ip地址之间相互解析的过程 ，知一出2  的过程 

### LDAP：
之支持ldap协议差汇总啊，深入了解LDAP 至关重要 

LDAP是 APP跟 其他的目录服务器进行通信的语言 没有之一  
是建立了 AD 跟其他网络系统之间通信的方式 没哟之一，线连接 到LDAP的服务器并且  AD中的域控会主动监听LDAP  并且进行查询链接的过程 

AD的 LDAP 的身份验证 ：
“BIND"操作来设置LDAP的会话 身份验证状态
类型 
1 `simple authentication`:佚名身份验证，等  
BIND指的是dns跟 IP地址相互交换的额软件 ，并且以bind向 LDAP 服务器进行身份安正 

2 `SASL Authentiation `SASL (简单身份验证跟安全层)  使用其他的身份验证服务 ，kerberos 这个 对LDAP进行身份验证


MSRPC 是 有四组关键接口 ：
![[Pasted image 20241029095006.png]]NTLM 身份验证 ：
两种身份验证方式  kerberos 跟ldap这两种外还提供如下两种验证协议 ：
AD的 应用程序跟服务使用  比如  LM  等等  
![[Pasted image 20241029095246.png]]
分开解析 LM：
最古老密码存储机制  
可能存放的地方为 ：1 WINDOW主机的sam数据库 跟域控以及 NTDS.DIT数据库中 
自 window server 2008以来默认关闭了 ，但是 和常见 尤其是用旧系统的大型环境中 
LM =14字符 且不区分大小写 总空间为60字符 且此密码使用hashcat相对容易
在这种hash的请况下  是 14个字符先对半分 如果 不够7个再 null代替，然后 进行 des秘钥加密，加密后 变为8个密文值，将其连接在一起产生lm哈希值，破解的时候只需要破解两耳7个的字符点即可 
![[Pasted image 20241029095755.png]]

NTLM （NT hash）
现代window的系统中的质询相应的身份协议验证机制 ，
说白了 在发送正式的密码数据前先发送确认数据先打好招呼，然后再发送数据不迟
hash攻击机的话 可以 时候用ntlm哈希想本地瓜里源 进行身份验证可能采用的时纯hash的事情并且无需提供ntlm的哈希的明文的值 

以某类型距离 ：
`以此hash距离 `
现有一个 hash的值如下 请帮助破解分析对应的信息 ：
````shell-session
Rachel:500:aad3c435b514a4eeaad3b935b51304fe:e46b9e548fa0d122de7f59fb6d48eaa2:::
````
具体个大部分分析如下：
如果看到了 这些信息的话 他氛围
1 Rachel 是用户名 
2 500是相对标识符 RID 500是 administrator 的账户已知的RID 
3 后面的部分是 LM哈希 如果禁止的话无任何用途
4在后面部分是 NT哈希 可以离线显示明文值  如下纤细 例如用crackmapexec工具如下：
使用crackmapexec工具的时候是需要与对方指定的ip地址以及对应的协议的问题建立起练习的 无法像hashcat那样互联 

NTLMv1
这个可以同时使用的是 nt跟lm哈希 并且 可以借助中级攻击破解  具体内容信息在帖子中看
https://byt3bl33d3r.github.io/practical-guide-to-ntlm-relaying-in-2017-aka-getting-a-foothold-in-under-5-minutes.html
Net-NTLMv1：
根据质询/相应算法创建的 先发送一个 8位的质询后再次进行返回询问 ，可能会遭受某些欺骗哦肝功能及 
Net-NTLMv2 这个 是上面的升级版本：
另外的一个是  
域缓存凭证 （MSCahche2）
身份验证的防范跟域主机通信的本质是 ，采用各种手段与 AD 中的DC进行通信，既 开发了 MScachev1 跟v2 算法  Dmian Cahce  Credentials  DCC  
加入域的主机 无法与域控通信问题的解决方昂视 ，
无法进行传递哈希攻击 ：既无法再只获得hash值的前提下进行攻击技术的执行

在遇到这种hash值的时候 不要尝试去通过工具破解  这可能是 mscache2 的访问数据信息  类似与 
`$DCC2$10240#bjones#e4e938d12fe5974dc42a90120bd9c90f`
如果凭证无法访问 dc的额话 主机自动将ten登录计算机的任何与用户 保存在 `HKEY_LOCAL_MACHINE\SECURITY\Cache`这种注册表中 

#### 用户跟本地用户配置问题可能造成的攻击方向 （了解大概 具体细节子啊后续中有介绍）
指的是未加入AD前创造的内容，个人程序能够登录计算机并且根据权限访问资源，验证密码并且创建访问令牌 等 内容 ，
管理员对组的内容进行分陪管理的过程 跟逻辑内容

配置管理账户是 ad 的核心 
可以利用这种机制对其用户机制进行网络攻击 利用配置错误的问题进行攻击的过程 

local account 本地账户：
local 被视为安全主体。只能管理单独独立主机的访问保护权限 并且 创建了几个默认的本地用户账户系统机制 
1、Adiminstior   特征：`SID=S-1-5-domain-500`:控制所有资源吧行窃不能被删除 跟锁定  ：window 10跟server2016 默认禁用内置管理员账户，
2、Guest:默认禁用信息，临时方可机制 ，并且 默认密码是空 建议保持禁用 
3、System (NT AUTHORITY \SYSTEM  这是个默认账户是一个服务用户  无配置文件 对主机所有的用户具有权限，无法添加到任何组 不会出现在用户管理器中，big你企鹅 可以支线 对所有文件的完全控制权 
4、Network service ：SCM用与window服务的预定义的本地账户，提供远程服务凭据
5、local service SCMwindow的另一个预定义的本地账户
https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts

### 域用户：
授予访问资源的权限  跟 所属组的去啊年  其中与用户账户可以登录整个域的任意一台主机 ，
account 这个 账户机制 是内置ad基础架构的本地账户，并且 可以当秘钥分发服务 后者黄金票证攻击 都基于这里展开的 提升域控制权并提升持久性 
用户命名属性：

| UserPrincipalName | 用户主要的登录名                |
| ----------------- | ----------------------- |
| ObjectGUID        | 唯一的额标识符即使用户删除也是唯一       |
| SAMccountName     | 支持以前版本的window客户端跟服务端用户名 |
| ObjectSID         | SID 用户组成员的身份            |
| sIDHistory        | 包含用户的先前的SID             |


是否加入域中计算机的区别 
加入：
拥有一个DC来收集资源等  域中的用户可以访问并且登录所有资源  
未加入 ：不受到与策略的管理，各个用户可以自定义  
但是 NT/ AUTHORITY这个机器账户跟与用户账户相同的凭据
。即使他未加入域 的话 可以在某台机器上通过system来执行横向移动的功能
Actrive Dircetory 组 
相似用户放在一起 分配权限，
用于分配组与组之间的管理的权限问题 

### 团体类型 
AD组的两个基本特征  type 跟 scope 
组的用途 是 group type   group scope显示如何在域跟林中用 ，租的类型是security 哥adistribution组

group scopes 创建新组分配三个不同的域：
1 domain local group 
本地组意味着不能作用到别的域上 本地组可以嵌套到本地组
2 global group 
创建全局账号 不限于本地组的权限问题 
3 universal group
通用组的用户可以出发全球同步进行  
用户中不同组之间的用户之间的区别问题 

通用组存放在 全局目录的gc中，并且 从通用组李曼添加或删除的话 触发整个林的复制，
全局组删除的话 影响的是单个域 ，而通用组影响的是整个林  影响范围会很广 而不是小小的一部分 
每次更改的时候触发全部林的复制 
组范围更改 ：
1 全局组之间互相无干扰的时候 转换为通用组，
 2本地组不包含任何的其他域作为程序员 将本地组转换为通用组
 3 通用转本地可以 权限大的转为小的可以 但是小的转大的不行 
 4 通用组 就单独存在不包含任何其他成员 才可转换为全局组

在这个其中会涉及很多比如提权的思路 可能从这里开始 ，他会有一些domain admins 这个是内置的本地安全组的环境，如果 B中的某个用户想访问A是不可以跨域访问的，而是必须添加到A中的组中才可以访问 


bloodhonud 这个工具能帮我们发现很多用户之家你的嵌套功能 

重要的群组属性：
cn ：AD中组的名称
member ：组成员的分布 
groupType ：指定组跟范围的整数 
member0f：：包含这个组的所有列表 
objectsid 是 唯一的sid 

#### AD 的权利跟特权：
利用  AD的权限提权的问题 通常可以做到 借此而提升权限的目的，比如 Ringts 分配跟用户组 处理access 对象权限 
然后 根据授权不同的问题 规划特定的范围的问题 
不同的组之间的权限分配所有不同 主要有如下常见的安全组 ：
https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups

| account operators               | 创建修改大多数类型的账户 可以登录到用户 但是无法管理这些                                 |
| ------------------------------- | ------------------------------------------------------------- |
| administrator                   | 整个域不完全访问权限                                                    |
| backup operators                | 备份恢复计算机上所有文件，在本地别适用于域管理员 ，这个是制作数据库的副本 ，借此提取凭证等信息内容。提取数据库的信息内容 |
| DnsAdmins                       | 权利访问dns信息，证明此台dc有dns访问的痕迹 曾经有过后者现在有                           |
| Domain  ADmins                  | 管理域的完全访问权限                                                    |
| domain computer                 | 创建计算机 组内 都在里面                                                 |
| domain contorller               | 包含所欲的dc  dc的组的集合体                                             |
| Doamin guset                    | dc内的访问来宾用户 可无密码访问的临时用户                                        |
| Domain User                     | 域内所有的用户账户                                                     |
| Enterprise ADMIn                | 完整的配置访问权限 进存在AD林根于  授予林范围更改                                   |
| Event Log reader                | 读取本地计算机时间日志  主机升级域控用的                                         |
| group policy creator owners     | 域中创建删除的组的对象                                                   |
| Hyper-V administrator           | 不受限制访问功能  利用hyper-v的工鞥成员被视为域管理员                               |
| IIS_IUSRS                       | 内置组                                                           |
| Pre-window 200compatible access | 向后兼容 一六的饿就配置，网络上任何人都可以借此访问信息 看见这个意味着有很多信息点可以从中泄露出去            |
| Print Operators                 | 成员域控以及AD的打印机的对象，本地登录DC 并且 恶意加载打印机程序 提升域内权限 利用打印机提权            |
| Protected Users                 | 获取额外保护 防止凭证盗窃跟kerberos                                        |
| read-only domain contorllers    | 域中所有的只读域控制器                                                   |
| remote desktop users            | rdp 权限                                                        |
| remote management users         | 这里是远程访问权限                                                     |
| schema admins                   | 膝盖ad架构 等  林根域 是组唯一成员                                          |
| server operators                | 存在域控上 并且服务员可以修挂此服务信息 没成员                                      |
|                                 |                                                               |

查看信息 ：
例如 
命令如下：
```powershell-session
 Get-ADGroup -Identity "Server Operators" -Properties *
```

命令解释如下：
1 Get-ADGroup 用于获取ad信息的cmdlet  查询指定信息
2 -Identity “server operators”：指定查询组的名称  以及SID  GUID 的全局标识符 
3 -Properties ：获取组属性的信息 所有信息 
![[Pasted image 20241030163350.png]]
具体信息如下分析：
查一查 domain admin 这个账户的权限 信息 透露出来的信息 ：
![[Pasted image 20241030163733.png]]
用户权限如何分配 ：
用户权限指的分配  可以用 sharpGPOAbuse 等工具分配目标权限的值 可以在域中执行所有操作者  
利用这个工具分配域的不同用户之间的权限问题 ：
https://github.com/FSecureLABS/SharpGPOAbuse
此处为滥用权限的技术进行ad提权的内容分析 ：
https://blog.palantir.com/windows-privilege-abuse-auditing-detection-and-defense-3078a403d74e
第二处：
https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens

### 查看用户的权限
当登录到主机后 使用域管理员权限提升工鞥
当进入后 除非我们子啊提升的上下文中运行 cmd或者powershell 控制台 ，否则的话window系统部会启动所有权限，UAC功能控制 
window提权的时候细说
`whoami /priv`
![[Pasted image 20241030165848.png]]
这里展示了window提权的问题  各种用户所在的权限分配的问题 

域管理员 权限提升 
根据展示的不同解释了 此时powershell 或者控制台所处的权限的不同 进而导致了UAAC权限的不同  

![[Pasted image 20241030170053.png]]
	提权后是这样的 然后以`SeShutdownPrivilege`这个功能提示我如果不是远程 可以直接操控关闭 dc 然后造成崩溃 
关于 AD的强化措施 ：
为了防止横向移动的可能  微软才哦也能给了 laps 这个随机化 跟轮换本地管理员来遏制这些发生 ：
https://www.microsoft.com/en-us/download/details.aspx?id=46899
设置日志监控等 ，包括修改ad对象等 防范横向移动等可能得攻击方式 
SCCM跟wsus的更新管理功能 :
WSUS  可以解决即使打补丁的功能 及时安装更新功能系统组织内容 
gmsa 与管理的账户  提供更高的安全级别 

### 检查组策略 
组策略是个winidow功能：
高级策略管理工具  进行配置的细节问题待处理,。
GPO 组策略对象 GPO 应用,应用user （s）策略虚拟机和computer   包括锁定超时，禁用usb端口，强制执行自定义的密码策略，GUID 
OU ，域或站点，本地的AD中上下文中。
GPO 的示例 ：
可以在当中配置一些组示例以及配置策略 



组策略对象 gpo 

在组策略中包含一些 规则的应用相关处理 例如
组策略可能借此来横向移动等特权共计技能 并且保持持久性靠这个 ，可能利用这些 细小的错误配置来放大缺口 来进一步打开突破口

对于gpo而言 每个gpo有唯一的名称 并且分配了唯一的标识符 GUID ：可连接到特定的ou以及 域或者站点的链接，一个GPO可以连接到多个容器中，这些设置不止可以应用到本地计算机中，还能存在于 AD的上下文中 去 

Order of precendence 来表达下面的规则应用 

| Local group Policy  | 策略定义在域外的本地主机上，如果更高级别的定义类似的设置，则均可被覆盖          |
| ------------------- | -------------------------------------------- |
| Site Policy         | 企业的单独策略 的配置规划 ，                              |
| Domain-wide Policy  | 在域中可以应用的任何设置类型以及配置                           |
| Organizational Unit | 影响特定的OU跟计算机，big你企鹅希望防止独特的设置，比如Powershell等的能力 |
| Any OU Policies     | 嵌套的OU 的特殊权限  以及一组 Applocker的策略设置             |

https://learn.microsoft.com/en-us/powershell/module/grouppolicy/?view=windowsserver2022-ps
上述这个工具可以帮助我们搞组策略的类型信息 

默认与策略是自动连接 并且连接到域的默认gpo ，并且他在所有的gpo中处于最高的优先级 且默认应用于所有的用户跟计算机 。


GPO的优先顺序：
当多个gpo连接到同一个OU的时候  首先处理 连接顺序为1 的  按照1234孙小虎处理 ，
首先  
![[Pasted image 20241031092457.png]]
这里 最左侧这个栏 ：link order 这个 栏中 ，如果代表为1 的gpo 具有最高端的优先级。然后是2 3 依次类推处理即可 

其中 Enforced 指的是基数较低的gpo强制覆盖所有的ou但是覆盖不了较低级别的 ，因为数字越小 执行度越优先执行
并且包含于他下面所有的gpo的设置，相当于让他下面的内容的东西强制进行执行的操作行为 ，

其中对于gpo强制规则理解是：
当一个 级别为5 的gpo被设置为强制后，他只会影响比它优先级高的 也就是5  6 7  等下面的  属于向下传递，且在同级中优先满足，但是针对与上级  234 中他还是不能强制执行的 

#### 默认域策略覆盖 

设计到两个选项的工作机制 ：
1 block inheritance  这是阻止继承 的装置，在特定的 ou上的时候 会让更高级别的gpo无法继承到下面的   也就是说无法影响到他们的下属
2 No Override 无覆盖 强制 
当设置了这个后 他的优先级是比 blockinheritance强的 也就是说 当这俩同时存在的时候 会优先执行无覆盖 ，也就是 无覆盖 强制继承制度，优先于阻止继承制度 ，
即使 有computer ou阻止了域级别的策略继承，但是No Override  的 Domain GOP仍会强制应用域该OU 的所有对象
3 补充说明，如果是Block inheritance 的话 也就是继承到他这里就截止了 并不会影响到他们后续所在的所有gpo当中

### 组策略刷新频率 
执行组策略更新  默认的时90分钟一次  对于每个 客户端     有一个活动期 +-30min  
因为 当设置了gpo后 需要有 2个h才可以生效，设置的目的是避免所有客户端从域控同时请求组而导致dc不堪重负

组策略中可以更改更新间隔 `force`启动更新过程，big你企鹅比较当前的计算机的域控等  
GPO这个系列可以借此来设置攻击  既攻破行管权限 
可以应用blood hunter 