#!/bin/sh

# PROVIDE: nebula
# REQUIRE: NETWORKING
#
# Copy this file to /usr/local/etc/rc.d/nebula and make it executable
# Add the following lines to /etc/rc.conf.local or /etc/rc.conf
# to enable this service:
#
# nebula_enable (bool): Set to NO by default.
#                       Set it to YES to enable it.
# nebula_user:          The user account the nebula daemon runs as.
#                       It uses 'root' user by default.
# nebula_conf:          The configuration file Nebula uses.    
#                       Default: /etc/nebula/config.yml
# nebula_flags:         Additional runtime flags.

. /etc/rc.subr
name="nebula"
rcvar="${name}_enable"
load_rc_config ${name}

: ${nebula_enable:="NO"}
: ${nebula_user:="root"}
: ${nebula_conf:="/etc/nebula/config.yml"}
: ${nebula_flags:=""}

command="/usr/sbin/daemon"
procname="/usr/local/bin/nebula"
command_args="-f ${procname} -config ${nebula_conf} ${nebula_flags}"

run_rc_command "$1"
