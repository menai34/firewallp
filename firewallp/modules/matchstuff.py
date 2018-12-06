# GNU General Public License <http://www.gnu.org/licenses/>.
# This file is fork from Ansible filter mathstuff.py

from __future__ import (absolute_import, division, print_function)

import collections


def difference(a, b):
    if isinstance(a, collections.Hashable) and isinstance(b, collections.Hashable):
        c = set(a) - set(b)
    else:
        c = unique([x for x in a if x not in b])
    return c


def unique(a):
    if isinstance(a, collections.Hashable):
        c = set(a)
    else:
        c = []
        for x in a:
            if x not in c:
                c.append(x)
    return c


def flatten(a):
    for item in a:
        if isinstance(item, collections.Iterable) and not isinstance(item, basestring):
            for x in flatten(item):
                yield x
        else:
            yield item
