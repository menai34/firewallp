#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

import argparse
import sys
from firewallp.cli import iptables


def __usage():
    sys.stdout.write("""
Usage: firewallp [OPTIONS...]
General Options
  start                Initialize iptables rules and restore it. 
  stop                 Flush all iptables rules and set ACCEPT default policy.
  reload              Initialize iptables rules and restore it.
Help Options
  -h, --help           Prints a short help text and exists
  -V, --version        Print the version string of firewallp
""")


def parse_cmdline():
    parser = argparse.ArgumentParser(usage="see firewallp usage",
                                     add_help=False)
    parser_group_startup = parser.add_mutually_exclusive_group()
    parser_group_startup.add_argument("-start", "--start", action="store_true")
    parser_group_startup.add_argument("-stop", "--stop", action="store_true")
    parser_group_startup.add_argument("-reload", "--reload", action="store_true")

    parser_group_standalone = parser.add_mutually_exclusive_group()
    parser_group_standalone.add_argument("-h", "--help",
                                         action="store_true")
    parser_group_standalone.add_argument("-V", "--version", action="store_true")

    return parser.parse_args()


def main():
    a = parse_cmdline()
    if a.help:
        __usage()
        sys.exit(0)
    if a.version:
        pass

    if a.start:
        iptables.start_iptables()
    if a.stop:
        iptables.stop_iptables()
    if a.reload:
        iptables.start_iptables()


if __name__ == "__main__":
    main()
