1 nmap扫描网段发现具体位置如下：
![[Pasted image 20240711182059.png]]
确认ip地址为192.168.166.114
进行nmap探测扫描：
详细信息扫描以后发现tcp开放端口就俩 
![[Pasted image 20240711182934.png]]
然后udp正在扫描中 
现在进行    1 详细目录爆破检查隐藏路径  2 继续对80端口http服务进行后续内容 
2 浏览器进入后发现页面如下：
![[Pasted image 20240711183942.png]]


观察源代码 后 进入到tiile的隐藏路径后  观察到信息点如图所示 
![[Pasted image 20240711183851.png]]
它提示wordpress 1.5.1.1这提示版本信息点 
3下方有个我那个很赞 进不去 将其域名加入到host文件尝试进入：
失败 
4 就看到提示词 google搜索 wordpress 1.5.1.1 发现有多个exp可以利用 下载下来 拷贝 到kali中 用searchsploit
![[Pasted image 20240711185848.png]]
将前三个拷贝下来后 
进行执行尝试 发现 ：
![[Pasted image 20240711185925.png]]
需找到对应的url 包含wordpress的链接 
而之前的80端口进入的显然没wordpress登录框 猜测是否藏起来了，去用gobuster进一步爆破发现
![[Pasted image 20240711190126.png]]
在此路径下进行目录爆破 ：
![[Pasted image 20240711190201.png]]
进入wp-admin后发现
sqlmap的输出：
etrieved: 'NickJames'
[07:38:47] [INFO] retrieved: '21232f297a57a5a743894a0e4a801fc3'
[07:38:47] [INFO] retrieved: 'hacker'
[07:38:47] [INFO] retrieved: '3dd7d62d3a3ba6d9b50617dc57aa40dd'
[07:38:47] [INFO] retrieved: 'MaxBucky'
[07:38:47] [INFO] retrieved: '50484c19f1afdaf3841a0d821ed393d2'
[07:38:47] [INFO] retrieved: 'GeorgeMiller'
[07:38:47] [INFO] retrieved: '7cbb3252ba6b7e9c422fac5334d22054'
[07:38:47] [INFO] retrieved: 'JasonKonnors'
[07:38:47] [INFO] retrieved: '8601f6e1028a8e8a966f6c33fcd9aec4'
[07:38:47] [INFO] retrieved: 'TonyBlack'
[07:38:47] [INFO] retrieved: 'a6e514f9486b83cb53d8d932f9a04292'
[07:38:48] [INFO] retrieved: 'JohnSmith'
[07:38:48] [INFO] retrieved: 'b986448f0bb9e5e124ca91d3d650f52c'
[07:38:48] [INFO] recognized possible password hashes in column 'u
sqlmap中可以自己进行hash的输出
sqlmap默认破解完hash值如下：
![[Pasted image 20240711194910.png]]
观察level中 等级 10 的管理员账户wield 
上传shellcode 的 后 支持反弹shell ， 
其借鉴了 ：
总结：尝试sql现有脚本未成功，进而尝试sqlmap 通过搜索的相关信息已知可能有sql注入 用sqlmap的进行注入自动尝试的过程 
sqlmap的问题 自动化 脚本 ！
