# DeltaProxyForwarder
1.服务端：
在服务器上执行
git clone https://github.com/RoyalAliceAcademyOfS ... warder.git
cd DeltaProxyForwarder/src
gcc dpForwarder.c -o dpForwarder

2.运行 ./dpForwarder 端口号，就会侦听udp端口，比如：
./dpForwarder 12349

3~6步骤请查看此链接：
https://github.com/RoyalAliceAcademyOfSciences/DeltaProxyGateway/blob/master/README.md

7.执行程序，测试效果
dpGateway <IP address> <Port>

testip="x.x.x.x"
iptables -I zone_lan_forward -p tcp -d $testip -j QUEUE
iptables -I FORWARD -t filter -p icmp --icmp-type ttl-exceeded -j DROP

testip为被墙reset封锁的ip，这个程序会把国内上传的请求通过udp中转到服务端，
然后tcp转发到testip(相当于ip伪造)，testip把下行通信直接发给国内的客户端，这时不经过服务端，有时速度相当快，相当于直连，
有时不稳定，包会被打散丢掉，我c没学好，折腾了两天搞不定这个不稳定的问题，有兴趣的朋友看看能不能进一步完善它。
