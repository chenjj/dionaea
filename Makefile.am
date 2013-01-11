# $Id$

AUTOMAKE_OPTIONS = foreign

SUBDIRS = src include modules

EXTRA_DIST = configure.ac conf/dionaea.conf.dist conf/hpfeeds.cfg.dist

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(sysconfdir)
	$(mkinstalldirs) $(DESTDIR)$(sysconfdir)/dionaea
	$(mkinstalldirs) $(DESTDIR)$(localstatedir)
	$(mkinstalldirs) $(DESTDIR)$(localstatedir)/run/
	$(mkinstalldirs) $(DESTDIR)$(localstatedir)/dionaea/
	$(mkinstalldirs) $(DESTDIR)$(localstatedir)/dionaea/binaries/
	$(mkinstalldirs) $(DESTDIR)$(localstatedir)/dionaea/bistreams/
	$(mkinstalldirs) $(DESTDIR)$(localstatedir)/dionaea/wwwroot/
	$(INSTALL_DATA) $(srcdir)/conf/dionaea.conf.dist $(DESTDIR)$(sysconfdir)/dionaea/dionaea.conf.dist;
	if [ ! -e $(DESTDIR)$(sysconfdir)/dionaea/dionaea.conf ]; then \
		$(INSTALL_DATA) $(srcdir)/conf/dionaea.conf.dist $(DESTDIR)$(sysconfdir)/dionaea/dionaea.conf; \
	fi
	$(INSTALL_DATA) $(srcdir)/conf/hpfeeds.cfg.dist $(DESTDIR)$(sysconfdir)/dionaea/hpfeeds.cfg.dist;
	if [ ! -e $(DESTDIR)$(sysconfdir)/dionaea/hpfeeds.cfg ]; then \
		$(INSTALL_DATA) $(srcdir)/conf/hpfeeds.cfg.dist $(DESTDIR)$(sysconfdir)/dionaea/hpfeeds.cfg; \
	fi
	$(mkinstalldirs) $(DESTDIR)$(localstatedir)/log


