#
# Regular cron jobs for the dionaea-nisl package
#
0 4	* * *	root	[ -x /usr/bin/dionaea-nisl_maintenance ] && /usr/bin/dionaea-nisl_maintenance
