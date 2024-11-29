此次任务目标：
1 ：借助前人留下的webshell进一步扩大战果 建立稳固的webshell 
2 ：继续枚举并且探索出后续相关道路

目标ip：10.129.211.41
第一步 尝试与webshell获取交互信息 ：
此时遇到的问题 :webshell可以正常交互但是无回显 ，问题 该如何解决 ？
![[Pasted image 20241126201528.png]]
看到观察到network中 /?frature=shell不分 穿个参数上去 进行交互即可 获得 
成功找到凭据
![[Pasted image 20241126201824.png]]
用户密码如下：
用户 mlefay 
密码：Plain Human work！

第二步 找到存放在内网网段的另外一台或者几台机器的ip地址 
信息如下：
![[Pasted image 20241127163911.png]]第三部 在webshell界面输入 
![[Pasted image 20241127164626.png]]
```
for i in $(seq 1 254); do (ping -c 1 172.16.5.$i | grep "bytes from" &) done
```
for i in $(seq 1 254)测试过 echo{1 254}不行 所以不适配bash 故用seq 列举1 到253到i上
 每一次循环中 操作是 (ping -c 1 172.16.5.$i)说明对此循环进行 枚举 i从 1 到254 一次枚举 
 但是枚举的过程中会有 很多信息 其中只需要陈工的  所以筛选出来 bytes from 
 grep"bytes from " &）进行异步曹组 后 done  别忘了 结束循环    & 在最后的目的是异步执行 并且 在后台执行的行为操作
观察有俩ip  一个是 5.15本机ip 另一个是 5.35 目的ip

 ![[Pasted image 20241127165458.png]]
第四步 已知 目标ip地址为 172.16.5.35 且 ip地址与该枢纽机 同网段 
尝试借助此枢纽点转向下一个ip地址
信息点 尝试ssh id_rsa 里面私钥通过 ssh -i链接成功 ，
但是问题是不知道
现阶段 是 ：
![[Pasted image 20241128193154.png]]
1利用无秘钥成功介入ssh链接到机器，
对应信息 ip：10.129.229.129  密码：未知   id_rsa(ssh)已知 已利用 ，介入内网地址 ：172.16.5.15
另外一个ip地址：172.16.5.35
现在需要解决的是无密码如何将文件连接上去 或者如何无密码连接传输上去 
通过ssh -D 9050 进行动态端口转发 
具体命令如下 ：
![[Pasted image 20241128195826.png]]
然后再确认 /etc/proxtchains.conf 这个信息最后一行是否配置为 9050 端口信息 观察本地代理端口地址 
![[Pasted image 20241128195931.png]]
确认端口信息无误，故直接使用proxychains代理即可 
现在问题是如何建立起 shell终端并且可以移动到 .35这个网段上去 
在msf 中的 ssh_login 一栏 中的

![[Pasted image 20241128203411.png]]
查找ssh_login 的装置 查找是否为ssh_login的登录窗口 
选中1 号  后输入 之前信中的信息 
![[Pasted image 20241128203508.png]]
![[Pasted image 20241128203732.png]]
设置对应的password 跟 username 侦测是否打开了ssh端口允许ssh运行
![[Pasted image 20241128203958.png]]
显示它允许 但是不能从msf走
那么直接从proxychains接入ssh即可获得 


lnessas 这个需要学习


