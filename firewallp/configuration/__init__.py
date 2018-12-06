# -*- coding: utf-8 -*-
#

import os.path
import firewallp

ETC_FIREWALLP = '/etc/firewallp'
ETC_FIREWALLP_CONF = ETC_FIREWALLP + '/firewallp.yml'
ETC_FIREWALLP_DNAT = ETC_FIREWALLP + '/dnat.yml'
ETC_FIREWALLP_FORWARD = ETC_FIREWALLP + '/forward.yml'
ETC_FIREWALLP_INPUT = ETC_FIREWALLP + '/input.yml'
ETC_FIREWALLP_MANGLE_PREROUTING = ETC_FIREWALLP + '/mangle_prerouting.yml'
ETC_FIREWALLP_MANGLE_INPUT = ETC_FIREWALLP + '/mangle_input.yml'
ETC_FIREWALLP_MANGLE_FORWARD = ETC_FIREWALLP + '/mangle_forward.yml'
ETC_FIREWALLP_MANGLE_OUTPUT = ETC_FIREWALLP + '/mangle_output.yml'
ETC_FIREWALLP_MANGLE_POSTROUTING = ETC_FIREWALLP + '/mangle_postrouting.yml'
ETC_FIREWALLP_OBJECTS = ETC_FIREWALLP + '/objects.yml'
ETC_FIREWALLP_OUTPUT = ETC_FIREWALLP + '/output.yml'
ETC_FIREWALLP_POLICY = ETC_FIREWALLP + '/policy.yml'
ETC_FIREWALLP_SERVICE = ETC_FIREWALLP + '/service.yml'
ETC_FIREWALLP_SNAT = ETC_FIREWALLP + '/snat.yml'
ETC_FIREWALLP_IPTABLES_TEMPLATE = os.path.dirname(firewallp.__file__) + '/configuration/templates/iptables-rules.j2'
ETC_IPTABLES = '/etc/sysconfig'
ETC_IPTABLES_RULES = ETC_IPTABLES + '/iptables'
BIN_IPTABLES_PATH = '/usr/sbin'
BIN_IPTABLES = BIN_IPTABLES_PATH + '/iptables'
BIN_IPTABLES_RESTORE = BIN_IPTABLES_PATH + '/iptables-restore'
BIN_IPSET_PATH = '/usr/sbin'
BIN_IPSET = BIN_IPSET_PATH + '/ipset'
