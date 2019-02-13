#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
import sys
from sys import argv

if len(argv) != 2:
    print("usage: %s <input-log>" % argv[0])
    sys.exit(1)

log = open(argv[1]).readlines()

nums = []

for x in log:
    parse = []
    for i in x.split(" "):
        try:
            n = int(i, 16)
            parse.append(n)
        except:
            pass
    if len(parse) == 0:
        continue
    assert len(parse) == 64
    nums.append(parse)

hexlines = []

for l in nums:
    s = ""
    for x in l:
        s += "\\x%02x" % x
    hexlines.append(s)

for x in hexlines:
    print('"' + x + '"')
