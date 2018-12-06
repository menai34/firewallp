from setuptools import setup, find_packages
from os.path import join, dirname
import firewallp

setup(
    name='firewallp',
    version=firewallp.__version__,
    packages=find_packages(),
    long_description=open(join(dirname(__file__), 'README.txt')).read(),
    include_package_data=True,
    install_requires=[
        'Jinja2 >= 2.9.6',
        'lxml >= 3.2.1',
        'PyYAML >= 3.12',
    ],
)
