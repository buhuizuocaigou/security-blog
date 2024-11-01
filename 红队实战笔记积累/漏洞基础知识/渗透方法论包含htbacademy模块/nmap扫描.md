1 sudo nmap -sT --min-rate 10000 -p- ip地址 -oA 输出的路径
2 sudo nmap -sT -sV -sC -O -p ip地址
3 sudo nmap --top-ports 20 ip地址 -oA 
4sudo nmap --script=vuln -p   ip地址 -oA 
灵活使用  
-sC  -sV 有时候可以不指定端口用

