class IPSetObjectsDataCollector(object):
    """
    IPSetObjectsDataCollector class
    """

    def __init__(self):
        self.ipset_collector = dict()

    @staticmethod
    def serialize():
        data = dict()
        return data

    def deserialize(self, data):
        pass

    def get_ipset_collector(self):
        return self.ipset_collector

    def add_ipset_collector(self, key, value):
        self.ipset_collector.update({key: value})

    def get_ipset_object_member(self, ipset_object):
        return self.ipset_collector.get(ipset_object)


class FirewallPServicesDataCollector(object):
    """
    FirewallPServicesDataCollector class
    """

    def __init__(self):
        self.services_collector = dict()

    @staticmethod
    def serialize():
        data = dict()
        return data

    def deserialize(self, data):
        pass

    def get_services_collector(self):
        return self.services_collector

    def append_service(self, key, value):
        self.services_collector.update({key: value})

    def get_service(self, service):
        return self.services_collector.get(service)


class IptablesPolicyDataCollector(object):
    """
    IptablesPolicyDataCollector class
    """

    def __init__(self):
        self.iptables_policy_collector = dict()

    @staticmethod
    def serialize():
        data = dict()
        return data

    def deserialize(self, data):
        pass

    def get_iptables_policy_collector(self):
        return self.iptables_policy_collector

    def add_iptables_policy_collector(self, key, value):
        self.iptables_policy_collector.update({key: value})

    def get_iptables_policy(self, iptables_policy):
        self.iptables_policy_collector.get(iptables_policy)


class IptablesRulesDataCollector(object):
    """
    IptablesPolicyDataCollector class
    """

    def __init__(self):
        self.iptables_rules_collector = dict()

    @staticmethod
    def serialize():
        data = dict()
        return data

    def deserialize(self, data):
        pass

    def get_iptables_rules_collector(self):
        return self.iptables_rules_collector

    def add_object_to_iptables_rules_collector(self, key, value):
        self.iptables_rules_collector.update({key: value})

    def get_object_from_iptables_rules_collector(self, iptables_object):
        self.iptables_rules_collector.get(iptables_object)


class IptablesLoggingDataCollector(object):
    """
    IptablesPolicyDataCollector class
    """

    def __init__(self):
        self.iptables_logging_collector = dict()

    @staticmethod
    def serialize():
        data = dict()
        return data

    def deserialize(self, data):
        pass

    def get_iptables_logging_collector(self):
        return self.iptables_logging_collector

    def add_object_to_iptables_logging_collector(self, key, value):
        self.iptables_logging_collector.update({key: value})

    def get_object_from_iptables_logging_collector(self, iptables_object):
        self.iptables_logging_collector.get(iptables_object)
