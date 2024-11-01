初次交互 ：
metasploit 提权 初步获得后 ：
直接shell 调用shell命令栏 

利用python的 import模块
命令  ：python -c ‘import pty; pty.spawn("/bin/sh")’
即可获得初步交互
具体解释如下：https://docs.python.org/3/library/pty.html
