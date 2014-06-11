# Makefile for syslearn
# Currently built as a kernel module
# Jun 11, 2014
# root@davejingtian.org
# http://davejingtian.org
obj-m += syslearn.o
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

