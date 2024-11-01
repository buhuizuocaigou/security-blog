一 侦查阶段  
 nmap扫描信息  ：
 ![[Pasted image 20240716152015.png]]
 其中 目标靶机所在网段为192.168.166.115  这个网段 
 进行 端口探测 
 1 ![[Pasted image 20240716152636.png]]
 注  此时ftp透露信息告诉我们 ，可以允许默认用户名密码登录 
2ftp进行登录后发现 ：将其包拷贝到本地 进行进一步分析 
![[Pasted image 20240716154717.png]]
![[Pasted image 20240716154732.png]]
进行进一步分析  


3  gobuseter 进行http80端口的目录遍历 ：
![[Pasted image 20240716154841.png]]
进入80端口 获得 图片两张 
分别为：
![[Pasted image 20240716154919.png]]
第二张 ；
![[Pasted image 20240716154948.png]]
已下载 侦测是否有隐写 
![[Pasted image 20240716155525.png]]
![[Pasted image 20240716155704.png]]



这个隐写无任何可以利用的信息  目前集中线索点在于一个 lol.pcap的包 

![[Pasted image 20240716160056.png]]
（除了wirshark我们还能用什么）集中攻破lol.pcap数据包 ：
打开wirshark 观察到  ![[Pasted image 20240716171422.png]]




后 分析  得到 一串名字 ：
![[Pasted image 20240716171449.png]]
下一个包是 txt文件  进行下载  
去到 file 里面 的 export objects 的 ftpdata 下载后 提示 如图所示 
![[Pasted image 20240716171614.png]]
进行拷贝下来后  
分析  
可以字典生成工具   但是对方是反爆破 只能爆破4条 也就是说是否可以用python写脚本 让他 循环爆破 ssh可鞥
如果限制次数 ：1 python 挂代理利用tor 挂代理进行智能ip脚本破解  4次换一个ip
2 
尝试将 Pass.txt 加入到密码蓝 进行 爆破尝试 ：
