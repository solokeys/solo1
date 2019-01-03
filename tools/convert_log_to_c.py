#
# Copyright (C) 2018 SoloKeys, Inc. <https://solokeys.com/>
#
# This file is part of Solo.
#
# Solo is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Solo is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Solo.  If not, see <https://www.gnu.org/licenses/>
#
# This code is available under licenses for commercial use.
# Please contact SoloKeys for more information.
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
    for i in x.split(' '):
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
    s = ''
    for x in l:
        s += '\\x%02x' % x
    hexlines.append(s)

for x in hexlines:
    print('"' + x + '"')
