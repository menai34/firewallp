from __future__ import print_function
from collections import OrderedDict
import yaml
import yaml.constructor

try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader


class OrderedDictYAMLLoader(yaml.Loader):
    """
    A YAML loader that loads mappings into ordered dictionaries.
    """

    def __init__(self, *args, **kwargs):
        yaml.Loader.__init__(self, *args, **kwargs)

        self.add_constructor(u'tag:yaml.org,2002:map', type(self).construct_yaml_map)
        self.add_constructor(u'tag:yaml.org,2002:omap', type(self).construct_yaml_map)

    def construct_yaml_map(self, node):
        data = OrderedDict()
        yield data
        value = self.construct_mapping(node)
        data.update(value)

    def construct_mapping(self, node, deep=False):
        if isinstance(node, yaml.MappingNode):
            self.flatten_mapping(node)
        else:
            raise yaml.constructor.ConstructorError(None, None,
                                                    'expected a mapping node, but found %s' % node.id, node.start_mark)

        mapping = OrderedDict()
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                hash(key)
            except TypeError as exc:
                raise yaml.constructor.ConstructorError('while constructing a mapping',
                                                        node.start_mark, 'found unacceptable key (%s)' % exc,
                                                        key_node.start_mark)
            value = self.construct_object(value_node, deep=deep)
            mapping[key] = value
        return mapping


class DataLoader:
    '''
    Class Dataloader
    '''

    def __init__(self):
        self.basedir = '.'

    def load_from_file(self, filename):
        """
        Loads data from a file, which can contain either YAML.
        """
        # read the file contents and load the data structure from them
        b_file_data = self._get_file_contents(filename)
        parsed_data = yaml.load(b_file_data, Loader=Loader)
        return parsed_data

    @staticmethod
    def _get_file_contents(filename):
        """
        Reads the file contents from the given file name
        """
        try:
            with open(filename, 'rb') as f:
                data = f.read()
            return data
        except (IOError, OSError) as e:
            print("an error occurred while trying to read the file '%s': %s" % (filename, str(e)))
