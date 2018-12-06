from firewallp.configuration.data import *
import types


class YAMLDictDotLookup(dict):
    """
    YAMLDictDotLookup class
    """
    def __init__(self, args):
        super(YAMLDictDotLookup, self).__init__(args)
        for arg in args:
            if isinstance(args[arg], dict):
                self.__dict__[arg] = YAMLDictDotLookup(args[arg])
            elif isinstance(args[arg], (list, tuple)):
                l = []
                for v in args[arg]:
                    if isinstance(v, dict):
                        l.append(YAMLDictDotLookup(v))
                    else:
                        l.append(v)
                self.__dict__[arg] = l
            else:
                self.__dict__[arg] = args[arg]

    def __getattr__(self, attr):
        return self.get(attr)

    def __delattr__(self, item):
        self.__delitem__(item)

    def __delitem__(self, key):
        super(YAMLDictDotLookup, self).__delitem__(key)
        del self.__dict__[key]


class IPSetObjectsDataManager(object):
    """
    IPSetObjectsDataManager class
    """
    def __init__(self, loader, sources=None):
        self._loader = loader
        self._ipset_odc = IPSetObjectsDataCollector()

        if sources is None:
            self._sources = []
        else:
            self._sources = sources

        self.__parse_source(self._sources)

    def add_ipset_collector(self, key, value):
        return self._ipset_odc.add_ipset_collector(key, value)

    def get_ipset_collector(self):
        return self._ipset_odc.get_ipset_collector()

    def get_ipset_object_members(self, ipset_object):
        return self._ipset_odc.get_ipset_object_member(ipset_object)

    def get_ipset_objects(self, obj=None):
        ipset_object_level_one = {}
        for k, v in self._ipset_odc.get_ipset_collector().items():
            if not isinstance(v, list):
                ipset_object_level_one.update({k: v})
        if obj:
            return ipset_object_level_one.get(obj, None)
        else:
            return ipset_object_level_one

    def get_ipset_list(self, obj=None):
        ipset_list = {}
        for k, v in self._ipset_odc.get_ipset_collector().items():
            if isinstance(v, list):
                ipset_list.update({k: v})
        if obj:
            return ipset_list.get(obj, None)
        else:
            return ipset_list

    def get_all_nested_ipset_objects(self, obj):
        tmp_data = self.__get_all_nested_objects(obj)
        result = list()
        self.__generators_to_list(tmp_data, result)
        return result

    def __generators_to_list(self, data, dictionary):
        if isinstance(data, types.GeneratorType):
            for i in data:
                if isinstance(i, str):
                    dictionary.append(i)
                else:
                    self.__generators_to_list(i, dictionary)
        elif isinstance(data, str):
            dictionary.append(data)

    def __get_all_nested_objects(self, obj):
        if isinstance(self.get_ipset_object_members(obj), list):
            for item in self.get_ipset_object_members(obj):
                if isinstance(self.get_ipset_object_members(item), list):
                    yield self.__get_all_nested_objects(item)
                elif self.get_ipset_object_members(obj):
                    yield str(obj)
                    break
        elif self.get_ipset_object_members(obj):
            yield str(obj)

    def __parse_source(self, source):
        parsed_data = self._loader.load_from_file(source)
        try:
            if parsed_data:
                for key, value in parsed_data.items():
                    self.add_ipset_collector(key, value)
        except TypeError as e:
            print("Error %s" % str(e))


class ItablesPolicyDataManager(object):
    """
    ItablesPolicyDataManager class
    """
    def __init__(self, loader, sources=None):
        self._loader = loader
        self._iptables_pdc = IptablesPolicyDataCollector()

        if sources is None:
            self._sources = []
        else:
            self._sources = sources

        self.__parse_source(self._sources)

    def add_iptables_policy_collector(self, key, value):
        return self._iptables_pdc.add_iptables_policy_collector(key, value)

    def get_iptables_policy_collector(self):
        return self._iptables_pdc.get_iptables_policy_collector()

    def get_iptables_policy(self, iptables_policy):
        return self._iptables_pdc.get_iptables_policy(iptables_policy)

    def __parse_source(self, source):
        parsed_data = self._loader.load_from_file(source)
        try:
            if parsed_data:
                for key, value in parsed_data.items():
                    self.add_iptables_policy_collector(key, value)
        except TypeError as e:
            print("Error %s" % str(e))


class IptablesRulesDataManager(object):
    """
    ItablesPolicyDataManager class
    """
    def __init__(self, loader, sources=None):
        self._loader = loader
        self._iptables_rulesdc = IptablesRulesDataCollector()

        if sources is None:
            self._sources = []
        else:
            self._sources = sources

        self.__parse_source(self._sources)

    def add_object_to_iptables_rules_collector(self, key, value):
        return self._iptables_rulesdc.add_object_to_iptables_rules_collector(key, value)

    def get_iptables_rules_collector(self):
        return self._iptables_rulesdc.get_iptables_rules_collector()

    def get_object_from_iptables_rules_collector(self, iptables_dnat):
        return self._iptables_rulesdc.get_object_from_iptables_rules_collector(iptables_dnat)

    def __parse_source(self, source):
        parsed_data = self._loader.load_from_file(source)
        try:
            if parsed_data:
                for key, value in parsed_data.items():
                    self.add_object_to_iptables_rules_collector(key, value)
        except TypeError as e:
            print("Error %s" % str(e))


class IptablesLoggingDataManager(object):
    """
    ItablesPolicyDataManager class
    """
    def __init__(self, loader, sources=None):
        self._loader = loader
        self._iptables_logging_dc = IptablesLoggingDataCollector()

        if sources is None:
            self._sources = []
        else:
            self._sources = sources

        self.__parse_source(self._sources)

    def add_object_to_iptables_logging_collector(self, key, value):
        return self._iptables_logging_dc.add_object_to_iptables_logging_collector(key, value)

    def get_iptables_logging_collector(self):
        return self._iptables_logging_dc.get_iptables_logging_collector()

    def get_iptables_logging_rules(self):
        iptables_logging_rules = list()
        if self.get_iptables_logging_collector().get('logging'):
            for k, v in self.get_iptables_logging_collector().get('logging').items():
                for items in v:
                    iptables_logging_rule = list()
                    iptables_logging_rule.append("-A logging {0}".format(self.__cmd_proto(k)))
                    iptables_logging_rule.append(self.__cmd_action(items.get('action'), items.get('properties')))
                    iptables_logging_rules.append(" ".join(iptables_logging_rule))
        return iptables_logging_rules

    def __parse_source(self, source):
        parsed_data = self._loader.load_from_file(source)
        try:
            if parsed_data:
                if parsed_data.get('iptables'):
                    for key, value in parsed_data.get('iptables').items():
                        self.add_object_to_iptables_logging_collector(key, value)
        except TypeError as e:
            print("Error %s" % str(e))

    @staticmethod
    def __cmd_proto(key):
        return {
            'tcp': '-p tcp',
            'udp': '-p udp',
            'icmp': '-p icmp',
            'unsorted': ''
        }.get(key, key)

    @staticmethod
    def __cmd_action(key, value):
        return {
            'NFLOG': '-j NFLOG %s' % value,
            'LOG': '-j LOG %s' % value
        }.get(key, '-j %s %s' % (key, value))


class FirewallPServicesDataManager(object):
    """
    FirewallPServicesDataManager class
    """

    def __init__(self, loader, sources=None):
        self._loader = loader
        self._firewallp_sdc = FirewallPServicesDataCollector()

        if sources is None:
            self._sources = []
        else:
            self._sources = sources

        self.__parse_source(self._sources)

    def append_service(self, key, value):
        return self._firewallp_sdc.append_service(key, value)

    def get_service(self, service):
        return self._firewallp_sdc.get_service(service)

    def get_all_ports_by_proto(self, service):
        tmp_data = self.__get_all_ports_by_proto(service)
        result = dict()
        self.__generators_to_dict(tmp_data, result)
        return result

    def __generators_to_dict(self, data, dictionary):
        if isinstance(data, types.GeneratorType):
            for i in data:
                self.__generators_to_dict(i, dictionary)
        elif isinstance(data, dict):
            data_look = YAMLDictDotLookup(data)
            if dictionary.get(data_look.proto):
                if isinstance(data_look.ports, list):
                    for item in data_look.ports:
                        dictionary[data_look.proto].append(item)
                else:
                    dictionary[data_look.proto].append(data_look.ports)
            else:
                dictionary.update({data_look.proto: []})
                if isinstance(data_look.ports, list):
                    for item in data_look.ports:
                        dictionary[data_look.proto].append(item)
                else:
                    dictionary[data_look.proto].append(data_look.ports)

    def __get_all_ports_by_proto(self, service):
        if isinstance(self.get_service(service), dict):
            yield self.get_service(service)
        else:
            if isinstance(self.get_service(service), list):
                for item in self.get_service(service):
                    yield self.__get_all_ports_by_proto(item)
            else:
                pass

    def __parse_source(self, source):
        parsed_data = self._loader.load_from_file(source)
        try:
            if parsed_data:
                for key, value in parsed_data.items():
                    self.append_service(key, value)
        except TypeError as e:
            print("Error %s" % str(e))
