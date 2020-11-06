#
# Regular cron jobs for the ssh2com package
#
0 4	* * *	root	[ -x /usr/bin/ssh2com_maintenance ] && /usr/bin/ssh2com_maintenance
