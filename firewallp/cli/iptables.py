from subprocess import Popen, PIPE, STDOUT, CalledProcessError
from firewallp.configuration import *
from firewallp.configuration.manager import *
from firewallp.modules.dataloader import DataLoader
from firewallp.modules import jinja2render
from firewallp.parser.iptables import parser as ipt_parser
from firewallp.modules import matchstuff
from firewallp.cli import ipset
import re
import difflib

loader = DataLoader()

ipt_mgr_policy = ItablesPolicyDataManager(loader, ETC_FIREWALLP_POLICY)
ipt_mgr_dnat = IptablesRulesDataManager(loader, ETC_FIREWALLP_DNAT)
ipt_mgr_snat = IptablesRulesDataManager(loader, ETC_FIREWALLP_SNAT)
ipt_mgr_forward = IptablesRulesDataManager(loader, ETC_FIREWALLP_FORWARD)
ipt_mgr_input = IptablesRulesDataManager(loader, ETC_FIREWALLP_INPUT)
ipt_mgr_output = IptablesRulesDataManager(loader, ETC_FIREWALLP_OUTPUT)
ipt_mgr_mangle_prerouting = IptablesRulesDataManager(loader, ETC_FIREWALLP_MANGLE_PREROUTING)
ipt_mgr_mangle_input = IptablesRulesDataManager(loader, ETC_FIREWALLP_MANGLE_INPUT)
ipt_mgr_mangle_forward = IptablesRulesDataManager(loader, ETC_FIREWALLP_MANGLE_FORWARD)
ipt_mgr_mangle_output = IptablesRulesDataManager(loader, ETC_FIREWALLP_MANGLE_OUTPUT)
ipt_mgr_mangle_postrouting = IptablesRulesDataManager(loader, ETC_FIREWALLP_MANGLE_POSTROUTING)
ipt_mgr_logging = IptablesLoggingDataManager(loader, ETC_FIREWALLP_CONF)


def __execute(command, return_output=False):
    process = Popen(command, shell=True, stdout=PIPE, stderr=STDOUT)
    output = ""
    # Poll process for new output until finished
    while True:
        next_line = process.stdout.readline()
        output += next_line
        if next_line == '' and process.poll() is not None:
            break

    exit_code = process.returncode

    if exit_code == 0:
        if return_output:
            return output
        else:
            return True
    else:
        # raise CalledProcessError(exit_code, command, output=output)
        print('Got error: %s' % output.rstrip())
        print ('Executed command: %s' % command)


def __split_objects_to_each_rule(data):
    ipt_chains = {}
    result = re.compile('set\s(?P<object>([\S]*\|[\S]*))\s')
    for chain, rules in data.items():
        ipt_rules = []
        for rule in rules:
            if result.search(rule):
                for m in result.finditer(rule):
                    if m.group(1):
                        objs = m.group(1)
                        for obj in objs.split('|'):
                            ipt_rules.append(str(rule).replace(objs, obj))
            else:
                ipt_rules.append(rule)
        ipt_chains.update({chain: ipt_rules})
    ipt_chains = __split_service_to_proto(ipt_chains)
    return ipt_chains


def __split_service_to_proto(data):
    ipt_chains = {}
    result = re.compile('dports\s(\S*)\s')
    for chain, rules in data.items():
        ipt_rules = []
        for rule in rules:
            if result.findall(rule):
                for m in result.findall(rule):
                    if m:
                        for obj in m.split('|'):
                            protos = obj.split(':')
                            if len(protos) > 1:
                                proto = obj.split(':')[0]
                                ports = obj.split(':')[1]
                                if '-' in ports:
                                    ports = ports.replace('-', ':')
                                ipt_rules.append("-p {0} {1}".format(proto, str(rule).replace(m, ports)))
                            elif '-' in obj:
                                tmp_obj = obj.replace('-', ':')
                                ipt_rules.append("{0}".format(str(rule).replace(obj, tmp_obj)))
                            else:
                                ipt_rules.append(rule)
            else:
                ipt_rules.append(rule)
        ipt_chains.update({chain: ipt_rules})
    return ipt_chains


def __restore_iptables_rules(iptables_rules=None):
    if iptables_rules:
        return __execute('%s -v < %s' % (BIN_IPTABLES_RESTORE, iptables_rules))
    else:
        return __execute('%s < /etc/sysconfig/iptables' % BIN_IPTABLES_RESTORE)


def __flush_iptables_tables():
    for table, policies in ipt_mgr_policy.get_iptables_policy_collector().items():
        __execute('%s -t %s -F -w 2' % (BIN_IPTABLES, table))
        __execute('%s -t %s -X -w 2' % (BIN_IPTABLES, table))
    return True


def __set_accept_iptables_policy():
    for table, policies in ipt_mgr_policy.get_iptables_policy_collector().items():
        for policy in policies:
            __execute('%s -t %s -P %s ACCEPT -w 2' % (BIN_IPTABLES, table, str(policy).upper()))
    return True


def __iptables_initial():
    ipt_policy_collector = ipt_mgr_policy.get_iptables_policy_collector()
    ipt_dnat_collector = ipt_mgr_dnat.get_iptables_rules_collector()
    ipt_snat_collector = ipt_mgr_snat.get_iptables_rules_collector()
    ipt_forward_collector = ipt_mgr_forward.get_iptables_rules_collector()
    ipt_input_collector = ipt_mgr_input.get_iptables_rules_collector()
    ipt_output_collector = ipt_mgr_output.get_iptables_rules_collector()
    ipt_mangle_prerouting_collector = ipt_mgr_mangle_prerouting.get_iptables_rules_collector()
    ipt_mangle_input_collector = ipt_mgr_mangle_input.get_iptables_rules_collector()
    ipt_mangle_forward_collector = ipt_mgr_mangle_forward.get_iptables_rules_collector()
    ipt_mangle_output_collector = ipt_mgr_mangle_output.get_iptables_rules_collector()
    ipt_mangle_postrouting_collector = ipt_mgr_mangle_postrouting.get_iptables_rules_collector()
    ipt_dnat_rules = __split_objects_to_each_rule(ipt_parser.init_rules(ipt_dnat_collector))
    ipt_snat_rules = __split_objects_to_each_rule(ipt_parser.init_rules(ipt_snat_collector))
    ipt_forward_rules = __split_objects_to_each_rule(ipt_parser.init_rules(ipt_forward_collector))
    ipt_input_rules = __split_objects_to_each_rule(ipt_parser.init_rules(ipt_input_collector))
    ipt_output_rules = __split_objects_to_each_rule(ipt_parser.init_rules(ipt_output_collector))
    ipt_mangle_prerouting_rules = __split_objects_to_each_rule(ipt_parser.init_rules(ipt_mangle_prerouting_collector))
    ipt_mangle_input_rules = __split_objects_to_each_rule(ipt_parser.init_rules(ipt_mangle_input_collector))
    ipt_mangle_forward_rules = __split_objects_to_each_rule(ipt_parser.init_rules(ipt_mangle_forward_collector))
    ipt_mangle_output_rules = __split_objects_to_each_rule(ipt_parser.init_rules(ipt_mangle_output_collector))
    ipt_mangle_postrouting_rules = __split_objects_to_each_rule(ipt_parser.init_rules(ipt_mangle_postrouting_collector))
    ipt_logging_rules = ipt_mgr_logging.get_iptables_logging_rules()
    ipt_vars = {'policy': ipt_policy_collector}
    ipt_vars.update({'nat': {}})
    ipt_vars.update({'mangle': {}})
    ipt_vars.update({'filter': {}})
    ipt_vars.update({'raw': {}})
    ipt_vars.update({'security': {}})
    ipt_vars['nat']['prerouting'] = ipt_dnat_rules
    ipt_vars['nat']['postrouting'] = ipt_snat_rules
    ipt_vars['mangle']['prerouting'] = ipt_mangle_prerouting_rules
    ipt_vars['mangle']['input'] = ipt_mangle_input_rules
    ipt_vars['mangle']['forward'] = ipt_mangle_forward_rules
    ipt_vars['mangle']['output'] = ipt_mangle_output_rules
    ipt_vars['mangle']['postrouting'] = ipt_mangle_postrouting_rules
    ipt_vars['filter']['input'] = ipt_input_rules
    ipt_vars['filter']['forward'] = ipt_forward_rules
    ipt_vars['filter']['output'] = ipt_output_rules
    ipt_vars['filter']['logging'] = ipt_logging_rules
    ipt_vars['raw']['prerouting'] = {}
    ipt_vars['raw']['output'] = {}
    ipt_vars['security']['input'] = {}
    ipt_vars['security']['forward'] = {}
    ipt_vars['security']['output'] = {}
    ipt_vars_dot = YAMLDictDotLookup(ipt_vars)
    ipset_destroy_objects = ipset.ipset_initialize(matchstuff.unique(ipt_parser.ipset_objects))
    exist_conf = open("/etc/sysconfig/iptables", 'r')
    ipt_rules_file = jinja2render.__render_iptables_rules(ETC_FIREWALLP_IPTABLES_TEMPLATE, ipt_vars_dot)
    if difflib.SequenceMatcher(None, exist_conf.read(), ipt_rules_file).ratio() < 1:
        jinja2render.__write_to_file(ETC_IPTABLES_RULES, ipt_rules_file)
        __restore_iptables_rules(ETC_IPTABLES_RULES)
    exist_conf.close()
    return ipset_destroy_objects


def stop_iptables():
    iptables_restored = __set_accept_iptables_policy()
    if iptables_restored:
        __flush_iptables_tables()
        ipset.cleanup_ipset_objects()


def start_iptables():
    ipset_destroy_objects = __iptables_initial()
    iptables_restored = __restore_iptables_rules(ETC_IPTABLES_RULES)
    if iptables_restored:
        ipset.destroy_ipset_objects(ipset_destroy_objects)
