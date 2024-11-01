1 mysql数据库 
## 确认是否安装MySQL

终端输入：mysql

如出现Welcome to the MariaDB monitor.  Commands end with ; or \g.则说明已经安装

如出现如下错误：ERROR 2002 (HY000): Can't connect to local MySQL server through socket '/var/run/mysqld/mysqld.sock' (2)，则说明mysql已经安装但缺少目录，需要执行如下操作：

1. root@kali:~#sudo mkdir -p /var/run/mysqld
2. root@kali:~#sudo chown mysql /var/run/mysqld/
3. root@kali:~#sudo service mysql restart


### 解决无法拖拽文件到kali的问题...：
在终端输入
sudo install open-vm-tools open-vm-tools-desktop
即可，之后sudo reboot
但是还是有可能出现不能拖拽的情况，此时可以尝试CTRL C，Ctrl V的形式进行虚拟机和外部机的文件交互，只不过比拖拽稍微麻烦一点点，但是效果是一样的，文字复制的话linux系统中是ctrl+shift+c和ctrl+shift+v，注意这点。


