#!/bin/sh
rm -f /tmp/dupreport
wget http://tz.pifii.com:9091/wifihome/file/udpreport.bin -O /tmp/udpreport
#wget http://192.168.2.157:9090/udpreport -O /tmp/udpreport
if [ -e "/tmp/udpreport" ]; then 
	cp /tmp/udpreport /usr/sbin/
	chmod 777 /usr/sbin/udpreport
	killall -9 udpreport
	/etc/init.d/udpreport restart
fi 

