1 NTFS 的特殊权限 ：
它具有以下的特殊权限 ：
1 能更改所有文件夹的ntfs去哪先
2 护犊子+向下兼容 = 用户拒绝访问文件夹级别呢荣光，也可以随意访问子文件的内容 
3 用户有权被禁止创建自己的子文件夹  但是 不能覆盖原先存在的内容 
NFTS 级别权限说白了就是管理员对用户可以在文件夹或文件中执行的操作更惊喜的控制，本地登录 或者远程登录的时候  只需要导航到文件系统即可访问到对应的文件系统中 

物流更新 ：
linux 下的rdp链接 window 建议用xfreerdp 
网络上的共享数据信息，将在上面创建网络共享window 10 的系统 

网络共享 ：
实验 window 10 的实验 
在系统中输入 该命令 来列出当前正在运行服务并且显示其中两个服务的信息  
命令分析如下：
````powershell-session
 Get-Service | ? {$_.Status -eq "Running"} | select -First 2 |fl
````
1 Get-Service: powershell 里面内置的cmdlet  获取本地或远程计算机所有服务状态信息 

![[Pasted image 20241006215643.png]]
在这条命令中的 Get-service 主要的应用瘦但是列出当前所有服务的进程 。注意 status 代表状态栏，而Name 反应的是进程的名字 ，同理 displayname 反映的是友好名称 ，也就是给人看的名字 相当于昵称 

Name 中反应的是 具体系统内部识别服务的名称 且这个名字可能人类不可读 

`?{$_.Status -eq "Running"}`
这个 ？ 指代的是 where- object  指的是 筛选的意思 
{$_}指代的时powershell中特殊符号 表示当期那的对象  一个对象表示一个服务 服务=对象 一一对应 
Status 指的是服务对象的某个属性类型 ，表示服务的当前状态  
-eq 、代指 过滤条件  
也就是连起来 是：？筛选信息 并且一个服务就是一个对象内容 过滤的类的名字是 Status 以及 -eq 选出status 中关键字是 Running 的 服务类型内容 
`select -First 2`
select 指的是 select-object 的cmdlet简写 ，选择对象的部分属性 或者指定数量的对像  跟java 的包封装管理类似

-First 2  指定前两个满足这个类型的 信独享服务 

![[Pasted image 20241006220443.png]]
如果要改成5个 就是这样的 -First 5  这种就是前五个 在running 里面的关键词内容 
 `|fl`:是 fromat-list 的缩写 将对象属性以列表格式表示，这样详细显示每个对象所有属性跟对应的值 
 上述是没加 `|fl`前 加入`|fl`后变为如下状态 
 ![[Pasted image 20241006220716.png]]
 其中name 跟display name 已经知道  
 dependentservices ：这个代指的是：依赖当前服务的其他服务内容 既为：依赖此服务的其余内容体系机制系统 。 哪些服务需要当当前服务运行  该name进程的 后置内容 
 
 也即使（） 括号内的信息代指的是 他要先运行完这个进程才可以运行其他的集成信息 
 2 Servicesdepended0n ：这个是 Getservvice 的CMDlet的实行之一   是该服务启动的前置条件  ：
 3Canpauseandcontinue：表示该服务是否支持暂停跟持续 ：返回的是一个布尔值：即为：
 当返回的是true  事后表明该服务支持 暂停跟继续操作
  false ：不支持暂停跟继续操作
插入：若 服务可以暂停  可以使用 `suspend-service`命令暂停他 并且 使用 `resume-service`接着执行 
使用与 某些需要暂停 但是不需要中断的服务机制  ，例如文件传输 ，媒体服务或者数据处理等 服务机制 
4 Canshutdown ：表示该服务是否在系统关闭的时候收到通知 。并且该服务返回的是一个布尔值 
True：关闭的时候 该服务会收到关闭通知
False ：当系统管你的时候 该服务不会收到任何通知。没有机会再关闭前做一些清理或者保存的状态的工作 
5 关机的时候的善后工作的话 比如保存数据 等  有用 
判断服务在系统关机种是否需要执行关键任务
6Canstop ：表示服务在进行的时候 是否可以被停止（即为完全终止服务内容）
   而 上面提到的暂停是可以随时按按钮恢复的 
7 Service Type ： 定义了一部分服务类型 ，表示他的运行的特点 例如：
(1) Win32ownprocess：
服务在独立的进程运行 不依赖其他服务
(2)Win32ShareProcess：
服务在共享进程中运行并且 ，与其他的服务共享进程 
（3）kerneldriver：
  是个内核驱动程序，指的是操作系统的内核交互相关类型 
  （4）FilesystemDriver：文件系统驱动程序 处理文件系统相关创造性为 与文件系统存储访问相关的东西 
  （5）Interactiveprocess：能否跟服务页面进行交互，允许服务在登录显示图形界面交互 
  （6）running 运行中 
  
  服务状态中 一共有三类服务权限 ：
  本地服务 网络服务跟系统服务 ，通常只有管理权限用户可以创建修改跟删除服务 其中服务权限配置错误是最常见的 权限提升的途径 没有之一 
  window s 中的关键并且核心的系统服务 ：关键 且核心指的是 在当中获取任意一个更新内容的话 必须 重启系统，如果不重启 无法停止 
  
   1 smss.exe(短信服务) : 系统管理员的回话工作，且负责的系统回话在这个系统中来 
   2 csrss.exe 执行程序部分 
   3 wininit.exe 这个是负责 .ini系列 的 列出安装后重启计算机要对window做的所有更改的工鞥 
   4 logonui.exe  这个是使用 登录模块在pc上 
   5 lsass.exe 官方的本地安全认证服务器登录PC 或者服务器有效性 生成 服务认证的进程 
   6 service  启动跟停止服务操作 
   7 system ：这个是运行window 内核后台进程 
  8 带有rpcss 的svchost.exe 管理动态链接库 .dll 这个的运行的系统服务  自动更新 等 window 防火墙 以及即插即用工鞥的服务 使用rpc以及rpcss机制 的服务 
  9带有Dcom 跟PNP的svchost.exe 包含window组件列表  包含关键核心的服务功能

关键进程 不能关闭，一旦关闭可能对系统或者本身造成重大影响的功能机制类型 ， 比如  WINDOW 的登录 系统 系统空闲的进程 window启动因公程序 客户端服务器运行时 window的回话挂力气 服务主机 跟本地安全机构子系统的功能机制 

### LSASS 本地安全机构子系统的服务机制：
lsass.exe 的神秘面纱 ：负责在window上执行安全策略进程 ，当用户尝试登录的时候 验证登录 并且 根据用户创建访问的领票，负责账户密码个更爱 ，关键是 与这个lsass.exe进程相关的时间  记录在window 安全日志中 
lsass.exe这个 工具比较重要  并且功能核心工鞥 
所以有不少渗透攻击方式 是根据这个事件展开运行的。

神奇的
其中 有个工具是window 的进程监控的工具 他他是通过 `\\live.stsinternals.com\tools`这个可以直接访问并且看到这个工具信息

这个工具套件可以监控系统上面运行的任何东西 包括tcpview psexec 等等 东西，可以发现有趣的过程以及提权路径或者横向移动的利器 
神奇的 sysinternals 工具套件系统 ：
https://learn.microsoft.com/en-us/sysinternals/
负责监视所有进程的东西的信息

#### 关于服务权限 所以 如何分配权限 以及如何利用他们成了至关重要的一个环节 已经内容 
提权  横向移动 利用的重要入口点跟一句信息 
利用服务权限配置错误进行配置 
window中 DHCP跟 AD 的系统网络服务通常得用管理员账户安装，包括使用指定的用户凭据信息分配特定的服务，并且凭据权限在用户上下文中设置 

主要受影响的是 DHCP（动态主机分配服务)以及Active Directory服务 等关键服务中 

注意服务权限以及 执行目录 的权限 可能使用恶意的dll 或者exe替换可执行文件路径 进行进一步的路径劫持的功能

### 使用servieces.msc检查服务。。

![[Pasted image 20241007174643.png]]
在 cmd 中的 敲入services 的.msc中 即可 看到如下 内容 ：
点进去 发现 有文件路径 等 信息 这些信息在 做横向等 行为的时候 以及域渗透的时候是至关重要的，需要多加重视学习 

需要注意的内置服务账户权限有以下三种：
1 localservice 
2 networkservice
3 localsystem



![[Pasted image 20241007175040.png]]
注意这里 在第一次失败下面 有几个选项 ：![[Pasted image 20241007175106.png]]
这里 重点注意 在重新启动服务 这个选项 ，也就是说 创建新账户仅用于运行服务  这个含义是当第一次失败的时候我们选择方式是运行某个程序或者是 等等
这里有一个可能得攻击点，就是在某程序失败后运行一个程序  这个程序可能会是我们写好的恶意脚本木马等内容信息
这是 攻击者可以合法利用的服务的一个途径之一 

使用SC检查服务 ：
sc可以用于配置跟管理服务类型  尝试如下命令：
![[Pasted image 20241007175831.png]]
这是 sc qc命令  后面跟的是 系统名称  也就是 service name  不是 耳熟能详便于记忆的 display_name 需要注意一下这个细节问题 ,可以利用sc 来启动 跟停止服务 ,

注意：当利用sc来启动跟停止服务的时候 是需要管理员权限才可以的 
下面 我尝试 借助管理员权限 修改指定服务的路径信息 :
![[Pasted image 20241007210516.png]]
那么为什么要这么做？
答：1 一旦能修改可执行路径后可以达到越权，以及执行恶意软件的目的，此时可修改路径定位到我们想执行的恶意软件内容即可 
2目的是检测是否具有管理员权限，因为只要拥有管理员权限才可以这么做 

这条命令修改后带来的改变 
![[Pasted image 20241007210703.png]]
这条命令 上下对比 发现执行路径发生了变化，这样在执行windowupdate的时候就会去执行 我们指定的那个 exe 路径信息 而不是他们真正的windowupdate  
这样可以达到插入恶意软件的技术的效果 

`sc config wuauserv binPath=xxxx/ccc/ccc`
这条命令解析如下：
1 sc config 这是对window 的解析命令 ，他在手册中的原文如下：
![[Pasted image 20241007211038.png]]
2 presistent 代指的是 持久的 
3  wuauserv 这个指的是服务的servicename  不是人们数值的displayname 
4binPath ：这个是修改默认的执行路径  ，在修改完这个后，意味着，我们执行这个服务前 的路径被修改位我们想让她执行的路径，既系统以为执行的是windowupdate 实际上改为了我们想让他执行的路径 
此条命令只有在内核态 root才可以被修改 
#### 5 另一种方式 ： sc sdshow wuauserv 
这条命令的核心是 利用每个服务背后都会有的一个ACL访问控制表，决定哪些用户哪些组可以进行操作  
判断是否具有修改服务的权限能力
![[Pasted image 20241007211654.png]]
在文档中是这么描述的 ：
![[Pasted image 20241007211717.png]]
descriptor ：描述 
对上述 解析 ：
注意 ：在window'中每个对象都是 可保护对象 也即是 说是 未命名既为可保护的对象信息，允许获取设置在window意外操作系统中的创建的额可安全对象的安全信息 
这里面有如下信息：
1 D：表示的时 DACL权限 也就是 现在见到的控制对对象的访问  
SACL 是用于 记录跟记录访问的尝试 
2 AU： 定义的安全主体经过身份验证的用户信息 
3 A;; 允许访问 ，  
4 CC ：SERVICE_QUERY_CONFIG  是想服务控制管理器 查询服务配置的一个  
SCM 服务控制管理器 主要复测配置远程管理信息的内容
5 LC ：SERVICE_QUERY_STATUS ：是向scm 的查询服务器当前的状态信息 的一个东西内容 
6SW：枚举依赖的服务列表 
7 RP  SERVICE STSRT   启动服务
LO 是 查询服务的当期那的状态  
8 RC 是 查询服务的安全描述符

他相当于是描述了在ACL表中的用户以及用户组的控制状态以及权限分布 

每个不同的权限 进行22一组拆分的时候 跟 进行单独存在的时候的含义是不一样的 

成对解释跟分开解释 的话 功能上跟权限上有不同的方式进行 



使用powershell 检查服务的权限 :
命令 `Get-ACL -Path HKLM:\System\CurrentControlSet\Services\wuarserv | Fromat-List`
各部分解析：
1 Get-ACL ：这个是 获取指定路径信息，的访问控制表 ACL 来获取这条路径可以访问的内容 ACL 表中的内容 来判断此路径的内容具有的权限信息 
2-Path  路径 
3HKLM  ：window注册表中的重要的选项没有之一，存储计算机系统跟硬件相关的配置信息内容包含计算机所有的硬件 注册更显 存放的是硬件相关的配置信息 ，包含硬件陪孩子以及系统配置信息 
在访问 HKLM 的时候注意权限设置 不当的可能会影响安全性 设计多款漏洞 包含 bluekeep漏洞分析 
4![[Pasted image 20241007230902.png]]
其中的截图分析  
OWNER 表示的是 ：此各个账户/组的权限问题 .  `NT AUTHORITY\SYSTEM` 这个是表示此注册表项由系统账户拥有 
BULTIN\Users:：  中的ALLOW Read key  这个指的是 用户可以读取注册表项 。
BULTINAdiministrators： 这个是达标了管理员的权限  FULLcontrol 表示对此有完全的控制权 
Creator owner allow 指的是 创造用户的组能力  
SDDL  是 安全描述符定义的语言信息 

提供安全描述符定义的语言  系统级别账户的 权限 
USER<Adminitor <system权限 
固权限问题  
权限问题是个重点问题 

Window 的会话：
加护会话： 本地登录 直接通过登录 或者runas 命令行 ==
非交互式： 有部分用户是无需用户名密码 即可登录的 
三种类型 ：本地系统账户 （local system 账户）本地服务账户（local service account），跟网络服务账户 （network service account）
系统启动的时候自动运行服务用的 
关于
1local system 这个 成为 NT AUTHORITY\SYSTEM账户 是window中权限最高的账户 属于域渗透中权限最高级的账户，这个权限比那个本地管理员权限组 的账户权限
提权等级最高权限等级（文件进程跟系统配置等 权限）
系统级服务权限  后期利用 一般是提权的目标 会从 adminster --->system权限



2本地服务账户： NT AUTHORITY\localservice 是system地区低权限版本，具有本地账户类似的权限，收益权限功能，启动某些服务
3 网络服务账户：该账户为 NT AUTHORITY\NetworkService 类似，标准域账户。本地计算机中类似的权限问题 某些访问
是域渗透里面登记最低的那档次 标准与用户，是本地计算机的本地账户的类似权限 经过身份验证类型会话

window的操作系统中可以jixninginteracting 的功能


#### graphical （图形化）的user功能

laboratory （实验室）
1970s开始的 ：GUI   interface for interacting（交互系统）
RDP功能是微软的看家系统，默认端口号 是user的端口号是3389端口开放运行，

back and forth 来来回回   远程链接到vpn的时候 可以通过rdp的方式进行连接然后达到远程办公链接的目的 

windows 命令行 ：
功能 
1、troubleshooting tasks 故障排除任务 
2、automation to perform certain tasks 自动化任务 类型
3 users to a domain at once 使用者使用的域名 
两种方式进行命令行互动  
1 Command prompt（CMD）
2 Powershell
![[ws-commands.pdf]]
原版的命令行合集  ：工具书 

CMD :
可以干例如 
1 perform more advanced（高级） tasks   
2 scheduled tasks
3creating  scripts
4batch（批处理） files 
5 
开启 cmd.exe有两种启动的方式  ：
方式一：直接在win+R中采用cmd 进行控制台直接启动 
方式二：以任何方式访问路径中的 ：`C:\Windows\system32\cmd.exe`

help命令可以直接 查看帮助文档 。或者是help+某个具体命令 
![[Pasted image 20241019101309.png]]
然后再帮助菜单中看到 任何一个命令后缀中加入 `<command>+/?`
这是帮助形式 
![[Pasted image 20241019101451.png]]
加入具体命令形式之后再加入 /?即可查看具体命令的内容模式 类型 

### Powershell 的命令功能形式 

Powershell主打的是微软设计更面向管理员的一款社戏  系统 ，Powershell 微软采用的底层架构是 .NET框架 的系统 ，能让管理员更方便的用命令行管理这个系统类型 ，互动类型较为优秀 
powershell 对文件系统更直接的访问 并且可以使用大部分命令行 

### Cmdlets
Cmdlet是powershell的调用的接口 是一个简易版本的powershell主要提供给我们去使用命令行，去方便在形如c#等模型上进行模块化调用的一个装置 ，
他的微软的官方网站如下图所示 ：https://learn.microsoft.com/en-us/powershell/scripting/developer/cmdlet/cmdlet-overview?view=powershell-7.4&viewFallbackFrom=powershell-7
可以通过自己定义 Cmdlet 来编写更复杂的任务模型 
powershell 可以支持更复杂的自动化脚本进行运行 并且接受的 

一些小命令
Cmdlets 动名词  所以可以通过一些命令形式来使用它去帮助你做事情 
1  Get-ChildItem 这个可以展示出来更多工作目录，
长这个样子 ![[Pasted image 20241019103053.png]]
也可以通过 后缀- 加tab来迭代他可以后面加的一些高级选项 或者说是选项分类

2 Get-Childltem -Reucurse （递归）
这项主要展示当前所处的工作目录以及下面所有的子目录的标志，采用的算法估计是二叉树的横向递归扫描算法，
![[Pasted image 20241019105431.png]]、如图所示 展示内容如下 
![[Pasted image 20241019105554.png]]
其中-Path 是切换 当期那命令所处的环境内容的 

Aliases (别名)
他都会存在一个别名就是比较好记的名字或者是缩写  
查询他的机制 是  `Set-Loacation`这个机制可以查询  其中 cd 或者sl也可以 切换路径 ，这是他们所代表的别名的含义 
![[Pasted image 20241019105905.png]]
我们可以采用某种语法形式 来 圪将新的别名添加进去 ，方便我们能快捷操作并且记忆 
添加并且查看是否已经添加进去，方便我们后续使用查阅：
![[Pasted image 20241019110233.png]]

查询某个Get-方法的时候的 帮助powershell 名称有 ：
`Get-help Get-xx方法`例如 
![[Pasted image 20241019110909.png]]
形如这种形式 的 帮助菜单

如何执行脚本 
`.\PowerView.ps1;Get-LocalGroup | fl`
具体解析如下 
PowerView.ps1：指的是一个域渗透中的信息搜集工具，主要用于当我们拿到立足点后进行信息搜集的过程中，可以借助此工具去枚举域的信息，给我们
然后 这个 Get-LocalGroup 是罗列出所有的组信息 显示所有的分组的信息
|fl 指的是采用列表的形式 累出 其中FL 的缩写是format-list 便于阅读 列表的形式列出并且便于阅读

### 执行策略 
如果我们发现无法再机器上运行特定的脚本的时候，可能系统采用了某种执行策略从而，让某种脚本执行得到了限制。因为 通过window配置的某种execution policy这个机制导致 阻止恶意脚本执行的策略发生
大体如表格所示
![[Pasted image 20241020085054.png]]、

ALLsinged ：所有脚本必须有签名，有来源者的签名，一旦发现之前未信任的将会发布提示
bypass ：绕过 一切正常
default ：默认的执行策略 ：![[Pasted image 20241020085525.png]]
是允许个人所有的命领航，但是不允许脚本运行  这是默认的执行策略
Remotesinged ： 外来的必须有数字签名认证表明来源是谁，但是本地的放行
undefined ：当前范围没执行策略，使用默认策略
Unrestricted ：这是费window执行策略 

展示执行策略  ：
`Get-ExecutionPolicy -List`
![[Pasted image 20241020085923.png]]
单命令无list 的是 显示当前所在的执行策略 就显示一个 
但是有-List 是列出所有的执行策略 
可以通过调整执行策略 或者是限制执行策略 或者在powershell脚本中限制执行策略来达到这一点
如何更改当下及昵称
`Set-ExecutionPolicy Bypass -Scope Process`
![[Pasted image 20241020090705.png]]
其中-Scope的后面那个部分 规定了更改的类型   
Set-ExecutionPolicy 这个揭示了我需要设置执行策略  Bypass揭示了我们要将-scope后面的执行策略更改为Bypass  策略   -Scope指定了他需要执行的范围方向问题 



WMI window管理规范  ：WMI是powershell子系统 提供了系统的监控工具


WMI 是主要提供window的监控工具的一个地方，他主要为了提供监控内容 以及一些状态信息
其中 WMI 的用途是:
1 本地远程的系统的状态信息
2 远程/APP安全的设置
3 更改用户或者组权限 
4设置修改系统属性
5代码执行 6调度
7设置日志记录

打开方式 ：直接在powershell中执行即可
![[Pasted image 20241020091621.png]]
命令各大解释 
1 wmic 是一个控制工具 
2 os ：是在 `wmic /?中找到的 如下所示：`
![[Pasted image 20241020091722.png]]
如果没有list 的话 他会显示的信息很乱 形如 ：
![[Pasted image 20241020091757.png]]
有了list 后依旧很乱，因为你不知道具体什么是关键信息 
形如：
![[Pasted image 20241020091834.png]]
可见list 有的时候只是单纯的列表功能，并不能把有用的信息展示在这里
综合可见，需要加入一个词 brief 
这个brief 将会自动提取有关信息并排列出来 
像这个样子 ：
![[Pasted image 20241020091959.png]]
这个是借助wmic 来获取os相关信息的内容的模块


2 第二种展示信息的模块： 
`Get-WmiObject`  
用法来源如下：![[Pasted image 20241020092643.png]]

网址如下所示：https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-wmiobject?view=powershell-5.1
查看此指定进程的信息如下图所示
![[Pasted image 20241020092734.png]]
如何查看对应的进程名字呢？
![[Pasted image 20241020093227.png]]
其中 指定筛选出来 | select-object Name ，ProcessID 这两列就好
指定具体是 Win32_Process这个win32进程姓名 
![[Pasted image 20241020093426.png]]
其最后的fl 跟ft的区别是 
一个fl 缩写是 format-list  另一个是 table  也就是一个是竖着列的 另一个是横着列的列表的形式展示出来的内容 

横向移动必备的模块部分 ：
https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/invoke-wmimethod?view=powershell-5.1
常用的横向移动的模块部分 用到这个 内容 


MMC ：Microsoft Manangement Console （MMC）
MMC：管理单元的 概念，并且允许管理员创建一个控制台并且添加远程或者本地的工具
开始菜单创建爱你mmc 即可 
![[Pasted image 20241020110243.png]]
在里面的add remove snap-in 这个里面去寻找到最需要的管理计算机的能力

WSL功能 ：linux二进制文件能在linux上运行的工鞥 可以下载linux 发行版本并且用它  
并且可以执行部分linux下运行的命令

### Window安全
单词 ：1 present 呈现 2 attack surface 攻击面 3even if 即使 4、
Security Identifier SID 这个程序
1 有一个安全的唯一表示付 也就是身份证 SID  这个是自动生成的，不同长度的字符串的值，并且存储在安全的数据库中，并添加到用户的访问令牌中去 ，帮助授权行为操作 
2 SID = Identifier  Authority    + Relative ID RID  如果是在AD 域环境中还包括 Domain ID这个东西。
3 观察命令 `whoami /user`
![[Pasted image 20241021110401.png]]
注意可以通过 whoami /? 查看相关指令帮助并且选择特定的指令帮助学习深思 
![[Pasted image 20241021110504.png]]
此时需要考验的是英文的阅读跟理解能力了 ，加油！
```powershell-session
(SID)-(revision level)-(identifier-authority)-(subauthority1)-(subauthority2)-(etc)
```
![[Pasted image 20241021110823.png]]
这是sid的主要架构 ，现在借助架构分析每一个字母分别代表的含义 ：

| number    | meaning | description                        |     |
| --------- | ------- | ---------------------------------- | --- |
| S         | SID     | 告诉你下面展示的是SID的标识符别认错了               |     |
| 1         | 修改的等级   | 到目前为止 这个数字默认都是1                    |     |
| 5         | 标识符     | 由48bit的字符串告诉你谁创建了这个SID  且SID的颁发者是谁 |     |
| 21        | 规则1     | 可变的数字 他告诉我我们以什么权威创建的这个数字系统         |     |
| blablabla | 顾泽2     | 告诉我们那个域或者是哪个电脑创建的这个数字              |     |
| 1002      | 规则3     | RID 揭示了用于区分这些用户是使用者还是说是group或者是管理员 |     |
5 表示是NT-AUTHORRIY 他是windowNT的安全的子系统生成的 
21-3792725.。。。这个表示的是独特的域标识符，表示了用户或者计算机所在的安全域部分，并且是域di的核心
1002是相标识符 1002 是指的系统中第二个创建的用户账户

SAM安全账户管理器 跟 ACE 访问控制的条目 
ACLs 是 contain 包容到 ACES中的 去定义里面的各种用户之间的权限的问题 揭示了不同用户所允许做的事情 ，比如说是groups 或者是 user所做的事情

ACLS：中包含两种 DACL 自主访问控制名单 跟 SACL 也就是系统访问控制名单 
DACL跟ACE：
https://learn.microsoft.com/en-us/windows/win32/secauthz/dacls-and-aces
具体内容总结如下：
在系统拥有DACL 的前提下，仅允许表中的允许的人进去 （进程访问）如果没在“邀请名单”上一概拒绝，DACL 的前提是 他由 ACE的东西构造，这个ACE列举了什么类型的组访问什么样名单上的内容，

如果没有DACL的话 任何人都可以访问这个系统 将不会遭受任何的限制
有个关键的特性是 ACE 表格中的顺序格外重要他是严格按照顺序读取的，也就是如果当ACE允许访问的时候但是我想给某些特殊人员提供特例的时候，需要把它单独提审出来放到队列的最前面，起码是在允许访问的前面，这样系统就会先执行拒绝 在后续执行访问，不然就会导致配置出现失误等问题的产生 
SACL 主要出现在域控制器上 ，在域控制器上负责访问表单等部分内容 


用户账户控制 UAC  ：
window的安全功能 ，存在的主要含义防止恶意软件运行或者操纵可能损坏计算机极其内容的进程 
UAC 的流程跟交互：https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works
具体细节总结如下：

1 儿子进程可以继承爹的令牌。且每个管理员访问令牌的app必须告知最终的用户程序
2 最小权限原则，完整级别低的管不了完整级别高的程序，如果标准user想使用访问令牌app时候 UAC要求用户提供有效的管理员凭据，

UAC登录流程：
管理员用户跟 普通用户的登录的唯一区别是他有一串由window颁发给管理员用户特定的程序token作为标识符存在 
这个访问令牌在登录的时候就创建完毕  。访问令牌=SID 跟window权限
权限提升的提示：当所有其他用户启动集成 继承的父进程的东西，所有东西开始的时候都默认由标准用户的身份登录，当管理员需要执行具有管理员部分的内容的时候，比如登录 等修改数据新给我的时候，window会自动提示用户批准，但是会提示用户，这时候才启用管理员tokern

一开始都是默认标准用户登录，等到启动了管理员权限部分的话才会启动管理员的token
这种行为是可以通过策略提升或者注册表进行配置的

UAC用户体验 ：标准用户的话 内置UAC是凭据提示  
管理员的话 是可以批准提示
UAC提升提示的时候，如果当app尝试使用管理员的完全访问令牌运行的时候，widnow首先分析exe确定发布者，
发布者氛围三类 ：window 出版商已签名  出版商未签名
灰色背景 是通过验证并且已发布的   黄色是未发布的  
	![[Pasted image 20241021150554.png]]
	路径 从最左侧的开始
	1 Userperforms operation 。。  以及后面的shellexecute 来看 ，他是这么逻辑 
	如果操作更改了文件系统或者注册表（resigned )的话，则 调用虚拟化，其他的所有的操作再次会调用shell execute （为什么呢？）因为shellexecute 的这个命令直接联系到提升的请求任务

2  直接出错误shellexecute中调用的createprocess 中查找到错误 借助这个报错机制进行的任务体系提升 
System：
系统权限的问题 去产生的提升的方法 做事情 

#### 注册表 编辑器 ：
window非常重要的数据库 存储window操作系统和选择的app的低级设置，分为计算机特定数据跟用户特定数据
同伙 win+r中的regedit打开
https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types
具体的注册表的信息的值如上述链接中所述.
注册表中包含有一些细节的信息值得商量跟探讨的过程 
其中有以下的信息可以注意的：
这是揭示了不同的type类型跟value的值的区别 ：


| Value                   | type                                                                                                                                                                                    |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |                                                                                                       asted image 20241022162314.png]]                                                                                                                                                    |
| REG_DWORD               | ![[Pasted image 20241022162431.png]]                                                                                                                                                    |
| REG_DWORD_LITTLE_ENDIAN | window最初涉及到小端的计算机                                                                  的头文件中定义为REG_DWORD             含有位扩展的环境变量 包含空字符的字符串，然后这个字符串是unicode还是ansi取决于是哪个函数 而且环境变量引用的函数是 ExpandEnvironmentstrings函数链接：                                              N    | 这个是大端计算机 其中 LITTLE_ENDI                                                                                                                                                                 |
| REG_                                                                                                                                           vironmentstrings函数链接：                                                                                                                                                                    https://learn.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-expandenvironmentstringsa

REG_EXPAND_SZ：环境变量的设置方式 ![[Pasted image 20241022163743.png]]

REG_LINK:
一个空字符结尾的unicode的字符串通过使用reg_OPTION_CREATE_LINK 这个调用reg函数创建符号链接的目标路径 

REG_MULTI_SZ:空字符\0结尾的字符串 


关于注册表的路径 
对于一般的普通注册表他放在 这里
`C:\Windows\System32\Config\`
对于 用户指定的注册表单元 他放在这里 
`C:\Users\<USERNAME>\Ntuser.dat`
在指定目录下 利用powershell开启 gci -Hidden 就能看到隐藏的文件信息跟注册表的内容
![[Pasted image 20241022164955.png]]
Run跟Runonce注册表项目 恶意软件
这些内容揭示了至此在os启动的时候或者用户的时候加载到内存中的 软件跟文件，观察当启动的时候加载那些文件格外的重要 
其中window注册表包含信息 有如下四个键 ：
```
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce

```
其中每个键表达含义不同 
`HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run`
这个信息简称为 HKEY_LOCAL_MACHINE
主要是HKLM ：全局的注册表的根键，并且用于存储整个计算机的设置，该路径下的所有程序会在每次系统启动的时候自动运行 无论登录的是哪个用户信息 且影响所有用户 并且在每次自启动的时候自己先执行一遍 
注：恶意软甲通常用这个保持持久化 ，window持久化行为的第一步 
`HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce`
与第一个不同的点在于Runone 
写入这个键的程序 仅会在下一次系统启动的时候执行一次，执行后自动删除对应的键值
`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`
重点关注：HKEY_CURRENT_USER部分的内容  简称为HKCU 保存当前的登录用户的注册表的配置问题
该键用户只会在当前用户登录到系统的时候启动 ，仅仅作用于当前用户的内容 
进影响当前用户，只针对用户设置的特定用户登录二用
`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce`
仅适用于当期那用户 且会在该用户下次登录的时候执行一次 并不会用于长期执行然后自己删除了
`reg 命令是专门针对注册表的命令`
reg query 这个命令功能主要针对于  查询注册表的键值 跟数据库命令差不多的内容给你
具体命令如下:
帮助列表如下：
![[Pasted image 20241022172639.png]]
这个展示了相对应的某种注册表的信息 

### 应用程序白名单 
建议实行白名单制度而不是黑名单制度的政策措施能力这样对系统个较为管理很恰当，只需要指定允许的内容，防止鳄鱼人爱你建 

applocker 指的是 微软的应用程序白名单解决方案  能够开工至用户可以运行那些app，能够精准控制app exe 等内容dll 等各种程序内容体系机制 

根据文件属性等等创建规则等
https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/applocker-overview

#### 本地组策略：
针对域环境中的 GPO 组策略 链接到所有加入到域的计算机上，也可以根据本地组策略在单个计算机定义这些，
并且组策略非域跟域都可以，
进入方式 是：
win +r 输入 gpedit.msc 
![[Pasted image 20241022173339.png]]
形如这种类型的 

### Window defender 防病毒软件：

非图形化的访问方式是 查看是否采用了那些保护设施 
![[Pasted image 20241022175053.png]]
这些揭示了window此时的defence 有哪些已经存在的保护措施，并且哪些是已开启的 是通过命令行发现的
练习 ： 
查询指定用户的sid  ：
首先注意 ：whoami/? 指定user 只能查询当前所在用户的uid  即为 htb-student的uid  
所以 我们的目标是如何查询指定用户的uid呢？
答案： 有两种思路，1 切换成指定用户 并执行whoami  但是会涉及到输入密码，在未知密码的情况下 不成立
2 直接使用pwoershell查询指定用户uid 

在执行之前 我们需要弄清楚究竟有多少个用户在这个系统上
故产生了 在widnwo下 查看所有用户的方法：
1 使用powershell查看所有的用户：
	方法一  ：用`Get-WmiObject `或者是`Get-LocalUser`这个来看本地用户（window10本地用户）
	`Get-WmiObject Win32_UserAccount|Select-Object Name,FullName,Status`
	效果如下:
	![[Pasted image 20241022213246.png]]
	其基本信息如下  ，如果想做进一步筛选的话可以用 ：
	`Get-WmiObject Win32_UserAccount | Select-Object Name,FullName,Status等想知道的关键词`
	经过合理筛选排版后如图所示，较为方便阅读 ：
	![[Pasted image 20241022213516.png]]
	其中关于Get-WmiObject 这个 是个函数，并且 win32_UserAccount 负责用户相关的方法管理功能机制问题 
	方法二：
	`Get-LocalUser`
	![[Pasted image 20241022214312.png]]
	这个的是显示本地用户 言外之意是如果有域的用户的话 使用Get-LocalUser的方法无法达成这个显示域用户的效果跟目的 
	方法三 ：利用CMD 
	![[Pasted image 20241022214449.png]]
	CMD中的net user 列出当前的所有的用户系统的所有用户的机制 
	方法四：使用wmic 在cmd下 是 一种工具合集的形式 
	![[Pasted image 20241022214628.png]]
	替换外化 如果 有adpowershell模块的话
	使用 `Get-ADUser -Fliter *`
	来列出所有的域用户 

当所有的用户列举完毕后 此时可以简易的查看到 用户的SID的信息 


技能评估测试：

创建一个新用户为JIM并取消User must change password logon选项
 步骤：
 1‘![[Pasted image 20241023153846.png]]
 选择computer management  
 然后进入 选择系统工具，本地用户跟组 选择用户
 右侧创建 user
 ![[Pasted image 20241023153925.png]]
 
 ![[Pasted image 20241023160447.png]]
 在左下方中 disable inheritance 这里指的是禁用继承
 除了gui模式还时常包含有各种的 powershell模式进行下去 
 