import re
from firewallp.configuration import *
from firewallp.configuration.manager import YAMLDictDotLookup
from firewallp.configuration.manager import IPSetObjectsDataManager, FirewallPServicesDataManager
from firewallp.modules.dataloader import DataLoader


loader = DataLoader()
ipset_mgr_objects = IPSetObjectsDataManager(loader, ETC_FIREWALLP_OBJECTS)
services = FirewallPServicesDataManager(loader, ETC_FIREWALLP_SERVICE)
ipset_objects = []

LIST_STATIC_ELEMENT = ['iif', 'oif', 'src', 'dst', 'service', 'ports', 'dnat', 'snat', 'state',
                       'accept', 'drop', 'reject', 'return', 'connmark', 'classify', 'tcpmss', 'ttl',
                       'tos', 'netmap'
                       ]

LIST_STATIC_ACTIONS = ['dnat', 'snat', 'accept', 'drop', 'reject', 'return', 'connmark', 'classify',
                       'tcpmss', 'ttl', 'tos', 'netmap'
                       ]

LIST_STATIC_ACTIONS_WITH_PREFERENCE = ['reject', 'connmark', 'classify', 'tcpmss', 'ttl', 'tos', 'netmap']


def __object_to_rule(value, static=False):
    new_value = ''
    obj = None

    if static:
        if ipset_mgr_objects.get_ipset_object_members(value):
            obj = ipset_mgr_objects.get_ipset_object_members(value)
            if isinstance(obj, str):
                ipset_objects.append(value)
                new_value = obj if not re.search('\/32', str(obj)) else str(obj).replace("/32", "")
    else:
        if ipset_mgr_objects.get_ipset_object_members(value):
            obj = ipset_mgr_objects.get_all_nested_ipset_objects(value)
            if isinstance(obj, list):
                for item in obj:
                    ipset_objects.append(item)
                new_value = "|".join(obj)
        else:
            new_value = obj
    return new_value


def __service_to_rule(value):
    obj = None
    if services.get_service(value):
        obj = services.get_all_ports_by_proto(value)
        new_value = ''
        for proto, ports in obj.items():
            if len(new_value) > 0:
                new_value += "|"
            new_value += proto + ":" + str(",".join(str(v) for v in ports))
    else:
        new_value = obj
    return new_value


class ConstDict(object):
    """An enumeration class."""
    _dict = None

    @classmethod
    def dict(cls):
        """Dictionary of all upper-case constants."""
        if cls._dict is None:
            v = lambda x: getattr(cls, x)
            cls._dict = dict(((c, v(c)) for c in dir(cls)
                             if c == c.upper()))
        return cls._dict

    def __contains__(self, value):
        return value in self.dict().values()

    def __iter__(self):
        for value in self.dict().values():
            yield value


class IptablesRulePatternConstruction(ConstDict):
    INBOUND_INF = 'iif\s(?P<inbound_inf>([\S]*))'
    OUTBOUND_INF = 'oif\s(?P<outbound_inf>([\S]*))'
    SOURCE = 'src\s(?P<source>([\S]*))'
    DESTINATION = 'dst\s(?P<destination>([\S]*))'
    SERVICE = 'service\s(?P<service>([\S]*))'
    PROTOCOL = 'proto\s(?P<protocol>([\S]*))(\sflags\s(?P<protocol_flags>[\w\s\,\-]*)(\s(%s)))?' % \
               '|'.join(LIST_STATIC_ELEMENT)
    PORTS = 'ports\s(?P<ports>([\S]*))'
    DNAT = 'dnat\s(?P<dnat>([\S]*))'
    SNAT = 'snat\s(?P<snat>([\S]*))'
    STATE = 'state\s(?P<state>([\S]*))'
    ACTION = '(\s)?(?P<action>(%s))' % '|'.join(LIST_STATIC_ACTIONS)
    ACTION_PARAMS = '(%s)\s(?P<action_params>(.*))$' % '|'.join(LIST_STATIC_ACTIONS_WITH_PREFERENCE)


def lookup_raw_rule_patterns(row, patterns):
    results = {}
    if isinstance(patterns, (list, tuple)):
        for v in patterns:
            result = re.compile(v)
            for m in result.finditer(row):
                if m:
                    results.update({key: value for key, value in m.groupdict().items()})
    else:
        result = re.compile(patterns)
        for m in result.finditer(row):
            if m:
                results.update({key: value for key, value in m.groupdict().items()})
    return results


def lookup_rule_object_collector(rule):
    results = {}
    for k, v in rule.items():
        if v:
            if re.match('^@', v):
                results.update({k: cmd_object_get(k, v)})
            else:
                results.update({k: cmd_standart_get(k, v)})
    return results


def cmd_standart_get(key, value):
    return {
        'action': '-j %s' % str(value).upper(),
        'action_params': '%s' % value,
        'logging': '-j logging',
        'destination': '-d %s' % value,
        'service': '--dport %s' % value,
        'source': '-s %s' % value,
        'inbound_inf': '-i %s' % value,
        'outbound_inf': '-o %s' % value,
        'protocol': '-p %s' % value,
        'protocol_flags': '%s' % value,
        'ports': '-m multiport --dports %s' % value,
        'dnat': '-j DNAT --to-destination %s' % value,
        'snat': '-j SNAT --to-source %s' % value,
        'state': '-m conntrack --ctstate %s' % value
    }.get(key, key)


def cmd_object_get(key, value):
    return {
        'destination': '-m set --match-set %s dst' % __object_to_rule(str(value).replace('@', '')),
        'service': '-m multiport --dports %s' % __service_to_rule(str(value).replace('@', '')),
        'source': '-m set --match-set %s src' % __object_to_rule(str(value).replace('@', '')),
        'dnat': '-j DNAT --to-destination %s' % __object_to_rule(str(value).replace('@', ''), static=True),
        'snat': '-j SNAT --to-source %s' % __object_to_rule(str(value).replace('@', ''), static=True),
    }.get(key, key)


def lookup_rule_object_iptables(data):
    rule = []
    tmp_dict = YAMLDictDotLookup(data)
    if tmp_dict.inbound_inf:
        rule.append(tmp_dict.inbound_inf)
    if tmp_dict.outbound_inf:
        rule.append(tmp_dict.outbound_inf)
    if tmp_dict.state:
        rule.append(tmp_dict.state)
    if tmp_dict.source:
        rule.append(tmp_dict.source)
    if tmp_dict.destination:
        rule.append(tmp_dict.destination)
    if tmp_dict.service:
        rule.append(tmp_dict.service)
    if tmp_dict.protocol:
        rule.append(tmp_dict.protocol)
    if tmp_dict.protocol_flags:
        rule.append('--%s-flags %s' % (str(tmp_dict.protocol).replace('-p ', ''), tmp_dict.protocol_flags))
    if tmp_dict.ports:
        if tmp_dict.protocol:
            rule.append(tmp_dict.ports)
    if tmp_dict.dnat:
        rule.append(tmp_dict.dnat)
    if tmp_dict.snat:
        rule.append(tmp_dict.snat)
    if tmp_dict.action:
        rule.append(tmp_dict.action)
    if tmp_dict.action_params:
        rule.append(tmp_dict.action_params)
    return " ".join(rule)


def init_rules(data):
    iptables_chains = {}
    for chain, rules in data.items():
        chain_name = re.sub('[\s.]', '_', chain)
        iptables_rules = []
        if isinstance(rules, list):
            for rule in rules:
                tmp_rule = {}
                for pattern in IptablesRulePatternConstruction():
                    tmp_rule.update(lookup_rule_object_collector(lookup_raw_rule_patterns(rule, pattern)))
                tmp_rule = dict((k, v) for k, v in tmp_rule.items() if v)
                completed_rule = lookup_rule_object_iptables(tmp_rule)
                if 'None' not in completed_rule:
                    iptables_rules.append(completed_rule)
                else:
                    pass
        iptables_chains.update({chain_name: iptables_rules})
    return iptables_chains
