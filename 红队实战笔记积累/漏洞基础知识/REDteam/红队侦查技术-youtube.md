被动侦查技术：场景 已知公司域名的地方 

1. 命令host xxx（xxx是目标公司的域名信息）
如图  所示：
![[Pasted image 20240706091032.png]]
2. nslookup xxx （域名信息）
![[Pasted image 20240706091133.png]]
3. 显示路由的命令   被转发了几次 也就是咱们到目标之间有几跳 
traceroute xxx （域名信息）
![[Pasted image 20240706091516.png]]
4. 探测dns信息的命令 ：
![[Pasted image 20240706091750.png]]
成为类似这样的命令 可以探测dnsrecon的具体信息细节 
5. 识别某域名是否有防火墙防护 命令功能如下:
![[Pasted image 20240706092229.png]]
6. 也可以用dig 探测dns 的可能的报文跟ip地址选项 
例如：
![[Pasted image 20240706092748.png]]
7. netcraft.com这个 网站可以查询一些的详细信息环节 
8. whatweb 是查询web一些信息 的 有助于我们做信息搜集
里面的一写信息指的琢磨 
9. firefox跟 chmoe的组件  wappalyzer的这个插件进行的 
可以提供网站的一些基础信息 ：这是属于被动侦查的部分
10. firefox 的 buildwith 跟 wappalyer 附件可以给砸门提供特定的信息
11. 
当确定相关title 的信息后 可以利用theHarverster 的主人公工具进行 进一步被动的信息搜集 已搜集域名相关信息来源

![[Pasted image 20240708182827.png]]
12. sublist3r   子域名的枚举功能 
看起来长这种模样 ：
    ![[Pasted image 20240711113935.png]]
13. google hack  and google docs
	 例如  site:xxx.com -site 或这这种形式的搜索内容 payload形式
	  等形式
	  可以利用inurl：加 特殊关键词的形式来锁定相关的后缀名 


主动搜集 与目标进行交互
 1. dnsrecon  工具  dnsrecon -d +域名 即可 对应到help相关文档后执行即可达到目的
 2. fierce 这个 暴力扫描ip域名以及dns信息的工具也可以透露 
 3. knockpy 这个是 一个域名枚举的工具信息 
 4. nmap 常规四件套 ：除外 可以用 ls -alps /usr/share/nmap/scripts 这个指令来查看可以使用什么nmap命令 脚本呢  默认的脚本 
![[Pasted image 20240716115746.png]]

 1. gobuster爆破 爆破路径   
 payload ：gobuseter dir -u http://blabla.com  -w /usr/share/dirbuster/wordlists/dir-medium blabal
注意   在写url的时候 /admin 定位的是文件  而 /admin/ 定位的是包含admin 的路径 的信息 

## Website Vulnerability Scanning
1 web漏洞扫描 ：
工具 是 nikto   ![[Pasted image 20240716120558.png]]

这是 nikto的工具帮助栏信息 其中需要注意的是 ：
