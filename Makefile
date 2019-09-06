CC		= gcc
CFLAGS          = -g -W -Wall -O2
OPTFLAGS        = -D_FILE_OFFSET_BITS=64

prefix          = /usr
bindir          = $(prefix)/bin
sbindir		= $(prefix)/sbin
datadir         = $(prefix)/share
docdir          = $(datadir)/doc/aircrack-ng

DESTDIR         = 
BINFILES        = airflood
SBINFILES	= airflood
DOCFILES        = README.txt
MANDESTDIR	= $(datadir)/man/man1

all: airflood

airflood: airflood.c
	$(CC) $(CFLAGS) $(OPTFLAGS) airflood.c -o airflood

install:
	install -d $(DESTDIR)$(bindir)
	install -m 755 $(BINFILES) $(DESTDIR)$(bindir)
	install -d $(DESTDIR)$(sbindir)
	install -m 755 $(SBINFILES) $(DESTDIR)$(sbindir)

uninstall:
	rm -f $(DESTDIR)$(bindir)/airflood
	rm -f $(DESTDIR)$(sbindir)/airflood
	

clean:
	rm -f airflood
