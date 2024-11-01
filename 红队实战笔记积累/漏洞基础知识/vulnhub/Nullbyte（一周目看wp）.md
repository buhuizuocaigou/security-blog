一 信息搜集 ：
1 ![[Pasted image 20240622145740.png]]
发现ip地址为 192.168.176.5
开始nmap四件套 
第一件套：
nmap 的端口发现扫描

![[Pasted image 20240622153855.png]]
二件套：
nmap的详细信息扫描
![[Pasted image 20240622153811.png]]
三件套：
nmap的默认漏洞扫描 ：
![[Pasted image 20240622154122.png]]
四件套 udp扫描：







phpmyadmin分析信息得到 一个是pmb服务 另一个是得到了一个hidden隐藏的token
用户名是target？
![[Pasted image 20240622172446.png]]


处理gif隐写后 
![[Pasted image 20240622175236.png]]




凭据是附加在url后面的 



进行hydra的爆破其中重点注意  
pyayload如下
破解两次 ：



hash如下：

![[Pasted image 20240622182325.png]]
![[Pasted image 20240622211216.png]]