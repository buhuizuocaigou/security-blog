
视频链接：https://www.youtube.com/watch?v=lNNJlu1KB2I
1被微软所谓的红色页面所阻拦导致的一切
当想访问的bloodhunter 的时候 微软的拦截界面很苦恼 比如：




步骤如下：1 进入该目录打开如下文件并且在最下方添加一些东西
![[Pasted image 20240419130810.png]]

在文件中打开后 在 最下方添加如下 
0.0.0.0 用wireshark  抓的googlesmart的网址  
针对google浏览器有：wireshark中输入 ip contains "ssl"出现类似于sb-ssl.google.com 这种类似的网址即可 附到后面 这就相当于是一个安全页面绕过  
或者针对 微软的 不让下载github上某个软件提示报错无法下载的问题 
有如下应对  在wireshark中输入 dns contains "smartscreen " 找到对应流量进行操作即可 

