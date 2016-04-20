#!/bin/sh 
#启动服务器 Mongodb,SSH,UWSGI服务

/etc/init.d/ssh start; ###启动ssh

mongod -f /etc/mongod.conf; ###加载mongod服务

uwsgi /wwwroot/koudaiguwen/uwsgi.ini; ###加载uwsgi服务

uwsgi /wwwroot/gushi/uwsgi.ini;

uwsgi /wwwroot/koudaizhuanjia/uwsgi.ini;

#uwsgi /wwwroot/tcpweb/uwsgi.ini;

#chmod -R a+w+r /wwwroot/test;

#cd /wwwroot/test;

#twistd -y server.tac; ###用tac文件 启动twisted服务守护模式

cron;

#chmod -R a+w+r /wwwroot/redis/redis-3.0.3;

#cd /wwwroot/redis/redis-3.0.3;

#/src/redis-server /wwwroot/koudaiguwen/redis.conf;