https://academy.hackthebox.com/module/112/section/1060
学习如何去进行足迹摸索 既 如何通过gobuster等信息搜集 指纹特征信息，发现自己这点比较欠缺
## 枚举原则 
在枚举中ONIST 单独分开执行  因为是  他是被动信息搜集  ，不主动与资源交互
注意核心目标 ：
枚举的原则一：环境模拟如下：当给已添加IT公司调查的时候 除了对目标任务进行dns等 基础的端口了解后 ，在得知ssh等信息后 下一步  要记得了解公司防御措施 及基础设置 ，而不是去着急进行爆破，
目标永远不是 去才用一种防范 而是尽可能采用多的方法进行 

注意关注到看不到的东西 ：
核心任务是 如何去利用他们 而不是像打靶机 那种一样对渗透技术测试 
记住一下原则  
1  事情远不止眼前所见。考虑所有观点 
2 区分看见跟看不见的 
3总有办法获取更多信息  了解目标
## 枚举方法 
有一套特定的方法   用于外部渗透测试 跟内部渗透测试的静态的枚举方法 
![[Pasted image 20240730155230.png]]
针对这类表格 进行层层枚举深入进行 
![[Pasted image 20240730155253.png]]
中文对照版
第一层 ：是 互联网存在 
目标如下：就是  专注于 调查的 目标  专注于某些固定目标以及资产进行渗透学习 
目标
```
the goal of this year layer(分层) is to identify(确认身份) all possible target systems and interfaces(接口) that can be tested
```
第二层  网关 （其他部分详细讲解 ）
了解详细的接口 以及如何达到目标的接口 程序不同的 工鞥呢   
```
the goal of is to understand what we are dealing with（处理） and what we have to watch out for (小心 期待 )
```
第三层 无障碍服务 本模块重点 
可访问服务  而言见擦汗每个目的地提供所有服务  ，服务每一个都有特定用途 是由ROOT特定安装 的 特定工鞥不同  需要理解他们的工作原理是啥 
``` 
goal is aims to understand the reason(原因) and functionality（功能） of the target system and the nessary（必要的） knowledge to communicate with it and exploit it for our purposes effectively（去利用它） 
```
第四层  Processes 
这个是用来处理 特定的pid号的 一个类型，进行数据处理   特定任务 pid号 有什么样的任务的一个层级 
```
goal here is to understand these factors and identify(因素) the dependencise（依赖）  between them  
```
第五层 权限层  
管理员分布权限在哪里，哪些环境 中 哪些用户具有什么权限 等 
这个一般存在于 Active Directory 这估摸是  的服务器中 用户负责挂管理多个领域 
```
it is crucial(至关重要的) to indentify these and understand  what is and is not possible with these privileges 
```
看看每个权限都干嘛 

第六层 ：操作系统设置 
看看操作系统的信息   ，到底啥 如何利用root权限搜集敏感信息 

不一定非得按照他按部就班操作 达成目的方法有很多，但是，目的结都一样 


## 域名系统 ：
在收集信息的时候重点关注其所在上线 的服务架构内容是啥 所有的技术框架是什么 技术结构是啥  
重点是技术跟结构 

在线状态 
### 在线状态  
第一步 解决  ：ssh 的证书信息 ：
通常ssh证书信息可以透露出他是那个服务器 他所在的域有多骚哥 
其查看 子域的来源 网站 1https://crt.sh/
引入证书透明度的机制链条  这个 是为了 加密的inter 的一种赎罪赠书的过程 其记录了在RFC 6962标准下的 能记录 颁发的所有数字证书的 痕迹，
防止伪造虚假证书 的信息 

ps正则表达式是编译原理的产物 
```shell-session
 curl -s https://crt.sh/\?q\=inlanefreight.com\&output\=json | jq .
```
这是 处理 利用crt.sh搜集相关信息后的产品 
其中各项命令解释如下：
1 curl -s （）开启silent的模式     也就是错误信息不输出 
2 `\?` 指的是 为了防止特殊字符？在shell中被误解
为啥？会在bash里面被误解呢 
因为在bash语法表达中  ？具有以下特殊含义：含义一 ：
形如```
```
ls file?
```
这种形式的 语句的话 会自动匹配 file1  file2 等模式 
但是只占一个字符  也就是说 file1 到file0  一个字符的就可 
如果是 file10  10占了两个字符他就匹配不到了
一个问号代表的是模糊查找 然后是通配符 
如果想查 file10   就加俩问号就行 `file??`
不仅可以使用数字 还可以使用任意的符号占据
![[Pasted image 20240730180235.png]]
第二个问号用途  返回值检查 
shell中 ?可以检查上一个命令的退出状态  
```
echo $?
```
这输入上一个命令的退出状态码  例如 
![[Pasted image 20240730180502.png]]
其中状态码各大表达形式如下：
![[Pasted image 20240730180557.png]]


