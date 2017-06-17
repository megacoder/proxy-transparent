VERSION = 1.4
CC	=gcc -std=gnu99
CFLAGS	=-Os -g -Wall '-DVERSION="$(VERSION)"' -pthread

all:: proxyt

proxyt:: proxyt.c
	$(CC) -o proxyt $(CFLAGS) proxyt.c -lpthread

install:: proxyt proxyt.rc proxyt.conf
	install -D -c -m 755 proxyt $(DESTDIR)/usr/sbin/proxyt
	install -D -c -m 755 proxyt.rc $(DESTDIR)/etc/rc.d/init.d/proxyt
	install -D -c -m 644 proxyt.conf $(DESTDIR)/etc/sysconfig/proxyt
	# install -D -c -m 644 proxyt.oracle.conf $(DESTDIR)/etc/sysconfig/proxyt.oracle

clean:
	rm -f *.o *~ a.out core.* lint tags

distclean clobber:: clean
	${RM} proxyt

export:
	dir=$$(mktemp -d /tmp/proxyt.XXXXXXXX) && \
	cvs export . $$dir/proxyt-$(VERSION) && \
	tar zvcf proxyt-$(VERSION).tar.gz -C $$dir proxyt-$(VERSION) && \
	rm -rf $$dir

