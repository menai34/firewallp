from subprocess import Popen, PIPE, STDOUT, CalledProcessError
from firewallp.configuration import *
from firewallp.configuration.manager import IPSetObjectsDataManager
from firewallp.modules import matchstuff
from firewallp.modules.dataloader import DataLoader
from firewallp.parser.ipset import parser as ipset_parser

import re


loader = DataLoader()
ipset_mgr_objects = IPSetObjectsDataManager(loader, ETC_FIREWALLP_OBJECTS)


def __execute(command, return_output=False):
    process = Popen(command, shell=True, stdout=PIPE, stderr=STDOUT)
    output = ''
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
        print('IPSet module got error: %s' % output.rstrip())
        print ('IPSet command: %s' % command)


class IPSetType(object):
    IPSET_HASH_NET = 'hash:net'
    IPSET_BITMAP_PORT = 'bitmap:port range 0-65535'
    IPSET_LIST_SET = 'list:set size 1024'


def __get_ipset_objects(ipset_object=None):
    if ipset_object:
        ipset_xml_data = __execute('%s -o xml list %s' % (BIN_IPSET, ipset_object), return_output=True)
    else:
        ipset_xml_data = __execute('%s -o xml list' % BIN_IPSET, return_output=True)
    return ipset_parser.get_xml_to_dic(ipset_xml_data)


def __set_ipset_object(ipset_object, ipset_type=IPSetType):
    __execute('%s create %s %s' % (BIN_IPSET, ipset_object, ipset_type))


def __add_ipset_object_member(ipset_object, ipset_member):
    __execute('%s add %s %s' % (BIN_IPSET, ipset_object, ipset_member))


def __del_ipset_object_member(ipset_object, ipset_member):
    __execute('%s del %s %s' % (BIN_IPSET, ipset_object, ipset_member))


def __flush_ipset_objects(ipset_object=None):
    if ipset_object:
        __execute('%s flush %s' % (BIN_IPSET, ipset_object))
    else:
        __execute('%s flush' % BIN_IPSET)


def __destroy_ipset_objects(ipset_object=None):
    if ipset_object:
        __execute('%s destroy %s' % (BIN_IPSET, ipset_object))
    else:
        __execute('%s destroy' % BIN_IPSET)


def __check_ipset_object_members(ipset_object, members):
    if not isinstance(members, list):
        members = [members if not re.search('\/32', str(members)) else str(members).replace("/32", "")]
    ipset_members = __get_ipset_objects(ipset_object)
    members_to_add = matchstuff.difference(members, ipset_members[ipset_object]['members'])
    destroy_members = matchstuff.difference(ipset_members[ipset_object]['members'], members)
    for member in members_to_add:
        if member:
            obj = ipset_mgr_objects.get_ipset_object_members(member)
            if not isinstance(obj, list):
                __add_ipset_object_member(ipset_object, member)
    for destroy_member in destroy_members:
        __del_ipset_object_member(ipset_object, destroy_member)


def __get_single_object(ipset_object, recursive=False):
    ipset_members = None
    if recursive:
        if ipset_mgr_objects.get_ipset_object_members(ipset_object):
            ipset_members = ipset_mgr_objects.get_ipset_object_members(ipset_object)
        if isinstance(ipset_members, list):
            return [__get_single_object(x, recursive=True) for x in ipset_members]
        else:
            return ipset_object
    else:
        if ipset_mgr_objects.get_ipset_object_members(ipset_object):
            ipset_members = ipset_mgr_objects.get_ipset_object_members(ipset_object)
        if not isinstance(ipset_members, list):
            return ipset_object
    return None


def destroy_ipset_objects(ipset_objects):
    for ipset_object in ipset_objects['list:set']:
        __destroy_ipset_objects(ipset_object)
    for ipset_object in ipset_objects['objects']:
        __destroy_ipset_objects(ipset_object)


def cleanup_ipset_objects():
    __flush_ipset_objects()
    __destroy_ipset_objects()


def ipset_initialize(ipset_objects):
    current_ipsets_objects = __get_ipset_objects()
    ipset_type_objects = []
    for ipset_object in ipset_objects:
        if __get_single_object(ipset_object):
            ipset_type_objects.append(ipset_object)
        else:
            obj = __get_single_object(ipset_object, recursive=True)
            ipset_type_objects.append(obj)
    ipset_type_objects = matchstuff.unique(list(matchstuff.flatten(ipset_type_objects)))
    ipset_type_lists = matchstuff.difference(ipset_objects, ipset_type_objects)

    for ipset_object in ipset_type_objects:
        ipset_members = None
        if ipset_mgr_objects.get_ipset_object_members(ipset_object):
            ipset_members = ipset_mgr_objects.get_ipset_object_members(ipset_object)
        if ipset_object in current_ipsets_objects:
            __check_ipset_object_members(ipset_object, ipset_members)
        else:
            if ipset_members:
                __set_ipset_object(ipset_object, IPSetType.IPSET_HASH_NET)
                __add_ipset_object_member(ipset_object, ipset_members)
    for ipset_object in ipset_type_lists:
        ipset_members = None
        if ipset_mgr_objects.get_ipset_object_members(ipset_object):
            ipset_members = ipset_mgr_objects.get_ipset_object_members(ipset_object)
        if ipset_object in current_ipsets_objects:
            __check_ipset_object_members(ipset_object, ipset_members)
        elif ipset_members:
            __set_ipset_object(ipset_object, IPSetType.IPSET_LIST_SET)
            for value in ipset_members:
                value_type = ipset_mgr_objects.get_ipset_object_members(value)
                if not isinstance(value_type, list):
                    __add_ipset_object_member(ipset_object, value)
    ipset_destroy_objects = {'objects': [], 'list:set': []}
    tmp_objects_list = ipset_type_objects + ipset_type_lists
    for ipset, properties in current_ipsets_objects.items():
        if ipset not in tmp_objects_list:
            if 'list:set' in properties['type']:
                ipset_destroy_objects['list:set'].append(ipset)
            else:
                ipset_destroy_objects['objects'].append(ipset)
    return ipset_destroy_objects

